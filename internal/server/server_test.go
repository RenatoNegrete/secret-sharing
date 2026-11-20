package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"secret-sharing/internal/ratelimit"
	"secret-sharing/internal/seal"
	"secret-sharing/internal/store"
)

// fakeStore mirrors the Redis store's atomic semantics with a mutex per call.
type fakeStore struct {
	mu   sync.Mutex
	data map[string]*fakeRec
}

type fakeRec struct {
	rec     store.Record
	views   int
	failed  int
	delHash []byte
	expires time.Time
}

func newFakeStore() *fakeStore { return &fakeStore{data: map[string]*fakeRec{}} }

func fk(id []byte) string { s := sha256.Sum256(id); return hex.EncodeToString(s[:]) }

func (f *fakeStore) get(id []byte) *fakeRec {
	r, ok := f.data[fk(id)]
	if !ok {
		return nil
	}
	if time.Now().After(r.expires) {
		delete(f.data, fk(id))
		return nil
	}
	return r
}

func (f *fakeStore) Create(_ context.Context, id []byte, n store.New) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[fk(id)] = &fakeRec{
		rec:   store.Record{Sealed: n.Sealed, HasPassphrase: n.HasPassphrase},
		views: n.MaxViews, delHash: n.DeletionHash, expires: time.Now().Add(n.TTL),
	}
	return nil
}

func (f *fakeStore) Peek(_ context.Context, id []byte) (store.Record, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.get(id); r != nil {
		return r.rec, true, nil
	}
	return store.Record{}, false, nil
}

func (f *fakeStore) Consume(_ context.Context, id []byte) (int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(id)
	if r == nil {
		return 0, false, nil
	}
	r.views--
	if r.views <= 0 {
		delete(f.data, fk(id))
		return 0, true, nil
	}
	return r.views, true, nil
}

func (f *fakeStore) FailUnlock(_ context.Context, id []byte) (int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(id)
	if r == nil {
		return 0, false, nil
	}
	r.failed++
	if r.failed >= store.MaxFailedUnlocks {
		delete(f.data, fk(id))
	}
	return r.failed, r.failed >= store.MaxFailedUnlocks, nil
}

func (f *fakeStore) Noop(context.Context) error { return nil }
func (f *fakeStore) Ping(context.Context) error { return nil }

func (f *fakeStore) DeletionHash(_ context.Context, id []byte) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.get(id); r != nil {
		return r.delHash, true, nil
	}
	return nil, false, nil
}

func (f *fakeStore) Delete(_ context.Context, id []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, fk(id))
	return nil
}

type harness struct {
	t   *testing.T
	srv *Server
	log *bytes.Buffer
	mu  *sync.Mutex
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func newHarness(t *testing.T, create, read *ratelimit.Limiter) *harness {
	t.Helper()
	buf, mu := &bytes.Buffer{}, &sync.Mutex{}
	logger := slog.New(slog.NewJSONHandler(lockedWriter{mu: mu, buf: buf}, nil))
	srv, err := New(newFakeStore(), logger, Options{
		PublicBaseURL: "http://localhost:8080",
		KDF:           seal.Params{ArgonTime: 1, ArgonMemoryKiB: 8 * 1024},
		CreateLimiter: create,
		ReadLimiter:   read,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, srv: srv, log: buf, mu: mu}
}

func (h *harness) do(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "10.0.0.1:5555"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec
}

func (h *harness) create(body string) createResponse {
	h.t.Helper()
	rec := h.do(http.MethodPost, "/secrets", body, nil)
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create: status %d body %s", rec.Code, rec.Body)
	}
	var cr createResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		h.t.Fatal(err)
	}
	return cr
}

func (h *harness) logs() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.log.String()
}

func TestCreateAndReadOnce(t *testing.T) {
	h := newHarness(t, nil, nil)
	cr := h.create(`{"content":"hello","ttl_seconds":60,"max_views":1}`)
	if len(cr.ID) != 64 || cr.ShareURL != "http://localhost:8080/s/"+cr.ID || cr.URL != cr.ShareURL || cr.DeletionToken == "" {
		t.Fatalf("bad create response: %+v", cr)
	}
	r1 := h.do(http.MethodGet, "/s/"+cr.ID, "", nil)
	if r1.Code != 200 || !strings.Contains(r1.Body.String(), `"content":"hello"`) {
		t.Fatalf("first read: %d %s", r1.Code, r1.Body)
	}
	if r2 := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r2.Code != 404 {
		t.Fatalf("second read: %d", r2.Code)
	}
}

func TestMaxViews(t *testing.T) {
	h := newHarness(t, nil, nil)
	cr := h.create(`{"content":"x","ttl_seconds":60,"max_views":3}`)
	for i := range 3 {
		if r := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r.Code != 200 {
			t.Fatalf("read %d: %d", i, r.Code)
		}
	}
	if r := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r.Code != 404 {
		t.Fatalf("4th read: %d", r.Code)
	}
}

func TestRaceExactlyOnce(t *testing.T) {
	h := newHarness(t, nil, nil)
	for range 20 {
		cr := h.create(`{"content":"race","ttl_seconds":60,"max_views":1}`)
		var wg sync.WaitGroup
		var mu sync.Mutex
		start := make(chan struct{})
		ok := 0
		for range 50 {
			wg.Go(func() {
				<-start
				if h.do(http.MethodGet, "/s/"+cr.ID, "", nil).Code == 200 {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			})
		}
		close(start)
		wg.Wait()
		if ok != 1 {
			t.Fatalf("expected exactly one success, got %d", ok)
		}
	}
}

func TestPassphraseAndFailedUnlocks(t *testing.T) {
	h := newHarness(t, nil, nil)
	cr := h.create(`{"content":"pp","ttl_seconds":60,"max_views":1,"passphrase":"correct horse"}`)

	if r := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r.Code != 401 {
		t.Fatalf("missing passphrase: %d", r.Code)
	}
	for i := range 4 { // missing passphrase above did not count; 4 wrong guesses keep it alive
		if r := h.do(http.MethodGet, "/s/"+cr.ID, "", map[string]string{"X-Passphrase": "wrong"}); r.Code != 401 {
			t.Fatalf("wrong guess %d: %d", i, r.Code)
		}
	}
	if r := h.do(http.MethodGet, "/s/"+cr.ID, "", map[string]string{"X-Passphrase": "correct horse"}); r.Code != 200 {
		t.Fatalf("correct after 4 wrong: %d", r.Code)
	}

	cr2 := h.create(`{"content":"pp","ttl_seconds":60,"max_views":5,"passphrase":"p"}`)
	for range 5 {
		h.do(http.MethodGet, "/s/"+cr2.ID, "", map[string]string{"X-Passphrase": "wrong"})
	}
	if r := h.do(http.MethodGet, "/s/"+cr2.ID, "", map[string]string{"X-Passphrase": "p"}); r.Code != 404 {
		t.Fatalf("after 5 failed unlocks expected 404, got %d", r.Code)
	}
}

func TestPassphraseChannels(t *testing.T) {
	h := newHarness(t, nil, nil)
	cases := map[string]func(id string) *httptest.ResponseRecorder{
		"header": func(id string) *httptest.ResponseRecorder {
			return h.do(http.MethodGet, "/s/"+id, "", map[string]string{"X-Passphrase": "pw"})
		},
		"body": func(id string) *httptest.ResponseRecorder {
			return h.do(http.MethodGet, "/s/"+id, `{"passphrase":"pw"}`, nil)
		},
		"query": func(id string) *httptest.ResponseRecorder {
			return h.do(http.MethodGet, "/s/"+id+"?passphrase=pw", "", nil)
		},
	}
	for name, read := range cases {
		cr := h.create(`{"content":"c","ttl_seconds":60,"passphrase":"pw"}`)
		if r := read(cr.ID); r.Code != 200 {
			t.Fatalf("%s: %d", name, r.Code)
		}
	}
}

func TestNotFoundShapes(t *testing.T) {
	h := newHarness(t, nil, nil)
	cr := h.create(`{"content":"c","ttl_seconds":60}`)
	tampered := cr.ID[:40] + strings.Repeat("A", 24) // same Lookup ID, wrong Secret Key
	for _, p := range []string{"/s/short", "/s/" + strings.Repeat("A", 64), "/s/" + tampered} {
		r := h.do(http.MethodGet, p, "", nil)
		if r.Code != 404 || strings.TrimSpace(r.Body.String()) != `{"error":"not_found"}` {
			t.Fatalf("%s: %d %s", p, r.Code, r.Body)
		}
	}
	if r := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r.Code != 200 {
		t.Fatalf("tampered reads must not consume a View: %d", r.Code)
	}
}

func TestRevoke(t *testing.T) {
	h := newHarness(t, nil, nil)
	cr := h.create(`{"content":"c","ttl_seconds":60}`)
	if r := h.do(http.MethodDelete, "/s/"+cr.ID, "", map[string]string{"Authorization": "Bearer nope"}); r.Code != 404 {
		t.Fatalf("wrong token: %d", r.Code)
	}
	if r := h.do(http.MethodDelete, "/s/"+cr.ID, "", map[string]string{"Authorization": "Bearer " + cr.DeletionToken}); r.Code != 204 {
		t.Fatalf("revoke: %d", r.Code)
	}
	if r := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r.Code != 404 {
		t.Fatalf("read after revoke: %d", r.Code)
	}
	if r := h.do(http.MethodDelete, "/s/"+cr.ID, "", map[string]string{"Authorization": "Bearer " + cr.DeletionToken}); r.Code != 404 {
		t.Fatalf("second revoke: %d", r.Code)
	}
	cr2 := h.create(`{"content":"c","ttl_seconds":60}`)
	if r := h.do(http.MethodDelete, "/s/"+cr2.ID+"?deletion_token="+cr2.DeletionToken, "", nil); r.Code != 204 {
		t.Fatalf("query revoke: %d", r.Code)
	}
}

func TestExpiry(t *testing.T) {
	h := newHarness(t, nil, nil)
	cr := h.create(`{"content":"c","ttl_seconds":1}`)
	time.Sleep(1100 * time.Millisecond)
	if r := h.do(http.MethodGet, "/s/"+cr.ID, "", nil); r.Code != 404 {
		t.Fatalf("expired read: %d", r.Code)
	}
}

func TestValidation(t *testing.T) {
	h := newHarness(t, nil, nil)
	big := strings.Repeat("a", maxContentBytes+1)
	cases := []struct {
		body  string
		code  int
		field string
	}{
		{`{}`, 400, "content"},
		{`{"content":""}`, 400, "content"},
		{`{"content":123}`, 400, "content"},
		{`{"content":"x","ttl_seconds":0}`, 400, "ttl_seconds"},
		{`{"content":"x","ttl_seconds":604801}`, 400, "ttl_seconds"},
		{`{"content":"x","max_views":0}`, 400, "max_views"},
		{`{"content":"x","max_views":101}`, 400, "max_views"},
		{`{"content":"x","passphrase":"` + strings.Repeat("p", 257) + `"}`, 400, "passphrase"},
		{`{"content":"` + big + `"}`, 413, "content"},
		{`not json`, 400, "body"},
	}
	for _, c := range cases {
		r := h.do(http.MethodPost, "/secrets", c.body, nil)
		var eb errorBody
		_ = json.Unmarshal(r.Body.Bytes(), &eb)
		if r.Code != c.code || eb.Field != c.field {
			t.Errorf("body %.40q: got %d field %q, want %d %q", c.body, r.Code, eb.Field, c.code, c.field)
		}
	}
	if r := h.do(http.MethodPost, "/secrets", `{"content":"x","extra":1}`, nil); r.Code != 201 {
		t.Errorf("unknown fields must be ignored: %d", r.Code)
	}
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	h := newHarness(t, nil, nil)
	for _, r := range []*httptest.ResponseRecorder{
		h.do(http.MethodGet, "/healthz", "", nil),
		h.do(http.MethodGet, "/s/nope", "", nil),
		h.do(http.MethodPost, "/secrets", `bad`, nil),
		h.do(http.MethodGet, "/nowhere", "", nil),
	} {
		if r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Referrer-Policy") != "no-referrer" ||
			r.Header().Get("Content-Security-Policy") == "" || r.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("missing headers: %v", r.Header())
		}
	}
}

func TestRateLimitIgnoresForwardedFor(t *testing.T) {
	h := newHarness(t, ratelimit.New(1, 3), nil)
	got429 := false
	for i := range 10 {
		r := h.do(http.MethodPost, "/secrets", `{"content":"x"}`, map[string]string{
			"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i), "X-Real-IP": fmt.Sprintf("198.51.100.%d", i),
		})
		if r.Code == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("spoofed forwarding headers bypassed the rate limit")
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	h := newHarness(t, nil, nil)
	const canary, pass = "CANARY-7f3a9c", "PASS-b81e44"
	cr := h.create(`{"content":"` + canary + `","ttl_seconds":60,"max_views":2,"passphrase":"` + pass + `"}`)
	h.do(http.MethodGet, "/s/"+cr.ID+"?passphrase=wrong", "", nil)
	h.do(http.MethodGet, "/s/"+cr.ID, "", map[string]string{"X-Passphrase": pass})
	h.do(http.MethodDelete, "/s/"+cr.ID, "", map[string]string{"Authorization": "Bearer " + cr.DeletionToken})
	m := h.do(http.MethodGet, "/metrics", "", nil).Body.String()
	logs := h.logs()
	share := []byte(cr.ID)
	for _, needle := range []string{canary, pass, cr.ID, string(share[:22]), cr.DeletionToken} {
		if strings.Contains(logs, needle) {
			t.Errorf("log leaked %q", needle)
		}
		if strings.Contains(m, needle) {
			t.Errorf("metrics leaked %q", needle)
		}
	}
	for _, ev := range []string{"secret.created", "secret.unlock_failed", "secret.viewed", "secret.revoked"} {
		if !strings.Contains(logs, ev) {
			t.Errorf("missing audit event %s", ev)
		}
	}
}
