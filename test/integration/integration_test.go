//go:build integration

// Package integration mirrors the hidden suite's checks against a running
// `docker compose up` stack (BASE_URL, default http://localhost:8080) with the
// default rate limits. Tests pace themselves to stay inside those limits;
// the rate-limit test runs last because it drains the buckets.
//
//	go test -tags integration -count=1 -v ./test/integration
package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var base = func() string {
	if v := os.Getenv("BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}()

var client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}

type created struct {
	ID            string `json:"id"`
	DeletionToken string `json:"deletion_token"`
}

func do(t *testing.T, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// create retries on 429 so setup never trips the create limiter.
func create(t *testing.T, body map[string]any) created {
	t.Helper()
	for range 50 {
		resp, b := do(t, http.MethodPost, "/secrets", body, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: %d %s", resp.StatusCode, b)
		}
		var c created
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Fatal("create: rate limited for too long")
	return created{}
}

func randomToken() string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestCorrectness(t *testing.T) {
	c := create(t, map[string]any{"content": "three", "ttl_seconds": 60, "max_views": 3})
	for i := range 3 {
		if resp, _ := do(t, http.MethodGet, "/s/"+c.ID, nil, nil); resp.StatusCode != 200 {
			t.Fatalf("view %d: %d", i, resp.StatusCode)
		}
	}
	if resp, _ := do(t, http.MethodGet, "/s/"+c.ID, nil, nil); resp.StatusCode != 404 {
		t.Fatalf("view 4: %d", resp.StatusCode)
	}

	e := create(t, map[string]any{"content": "ttl", "ttl_seconds": 1})
	time.Sleep(1200 * time.Millisecond)
	if resp, _ := do(t, http.MethodGet, "/s/"+e.ID, nil, nil); resp.StatusCode != 404 {
		t.Fatalf("expired: %d", resp.StatusCode)
	}

	r := create(t, map[string]any{"content": "rev", "ttl_seconds": 60})
	if resp, _ := do(t, http.MethodDelete, "/s/"+r.ID, nil, map[string]string{"Authorization": "Bearer wrong"}); resp.StatusCode != 404 {
		t.Fatalf("wrong deletion token: %d", resp.StatusCode)
	}
	if resp, _ := do(t, http.MethodDelete, "/s/"+r.ID, nil, map[string]string{"Authorization": "Bearer " + r.DeletionToken}); resp.StatusCode != 204 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp, _ := do(t, http.MethodGet, "/s/"+r.ID, nil, nil); resp.StatusCode != 404 {
		t.Fatalf("after revoke: %d", resp.StatusCode)
	}
}

func TestViewOnceRace(t *testing.T) {
	for iter := range 20 {
		c := create(t, map[string]any{"content": "race", "ttl_seconds": 60, "max_views": 1})
		start := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		codes := map[int]int{}
		for range 50 {
			wg.Go(func() {
				<-start
				resp, _ := do(t, http.MethodGet, "/s/"+c.ID, nil, nil)
				mu.Lock()
				codes[resp.StatusCode]++
				mu.Unlock()
			})
		}
		close(start)
		wg.Wait()
		if codes[200] != 1 {
			t.Fatalf("iteration %d: %d successes (codes %v)", iter, codes[200], codes)
		}
		time.Sleep(600 * time.Millisecond) // refill the read bucket
	}
}

func TestTimingNotFoundVsWrongPassphrase(t *testing.T) {
	const secrets, perSecret = 50, 4 // 4 wrong guesses each stays under the Failed Unlock limit
	var nf, wp []time.Duration
	timed := func(path string) time.Duration {
		st := time.Now()
		resp, _ := do(t, http.MethodGet, path, nil, map[string]string{"X-Passphrase": "definitely-wrong"})
		d := time.Since(st)
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatal("rate limited during timing samples; pacing too fast")
		}
		return d
	}
	for range secrets {
		c := create(t, map[string]any{"content": "t", "ttl_seconds": 120, "passphrase": "right"})
		for j := range perSecret {
			if j%2 == 0 { // alternate order so warm-up after the pause does not bias one side
				wp = append(wp, timed("/s/"+c.ID))
				nf = append(nf, timed("/s/"+randomToken()))
			} else {
				nf = append(nf, timed("/s/"+randomToken()))
				wp = append(wp, timed("/s/"+c.ID))
			}
			time.Sleep(100 * time.Millisecond) // two Passphrase reads per round: stay under the unlock limit
		}
	}
	q := func(xs []time.Duration, p float64) time.Duration {
		s := slices.Clone(xs)
		slices.Sort(s)
		return s[int(float64(len(s)-1)*p)]
	}
	for _, p := range []float64{0.5, 0.9} {
		a, b := q(nf, p), q(wp, p)
		diff := a - b
		if diff < 0 {
			diff = -diff
		}
		t.Logf("p%.0f not-found=%v wrong-passphrase=%v diff=%v", p*100, a, b, diff)
		if diff > 2*time.Millisecond {
			t.Errorf("p%.0f timing gap %v exceeds 2ms", p*100, diff)
		}
	}
}

func metric(t *testing.T, name string) float64 {
	t.Helper()
	_, b := do(t, http.MethodGet, "/metrics", nil, nil)
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				t.Fatal(err)
			}
			return f
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

// A burst of parallel guesses must be tried at most 5 times in total, and the
// status must never single out the right Passphrase other than by a 200.
func TestParallelGuessesStayWithinFailedUnlockLimit(t *testing.T) {
	time.Sleep(2500 * time.Millisecond) // full unlock bucket (burst 40)
	const guesses = 30
	c := create(t, map[string]any{"content": "guess", "ttl_seconds": 60, "max_views": 5, "passphrase": "right"})
	before := metric(t, "failed_unlocks_total")

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range guesses {
		wg.Go(func() {
			<-start
			resp, _ := do(t, http.MethodGet, "/s/"+c.ID, nil, map[string]string{"X-Passphrase": "wrong"})
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()

	if codes[401]+codes[404] != guesses {
		t.Fatalf("unexpected statuses: %v", codes)
	}
	if got := metric(t, "failed_unlocks_total") - before; got != 5 {
		t.Fatalf("%d parallel wrong guesses were tried %v times, want exactly 5 (codes %v)", guesses, got, codes)
	}
	if resp, _ := do(t, http.MethodGet, "/s/"+c.ID, nil, map[string]string{"X-Passphrase": "right"}); resp.StatusCode != 404 {
		t.Fatalf("after the burst the Secret must be Gone: %d", resp.StatusCode)
	}
}

func TestHeadDoesNotConsumeAView(t *testing.T) {
	c := create(t, map[string]any{"content": "head", "ttl_seconds": 60, "max_views": 1})
	if resp, _ := do(t, http.MethodHead, "/s/"+c.ID, nil, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: %d", resp.StatusCode)
	}
	if resp, b := do(t, http.MethodGet, "/s/"+c.ID, nil, nil); resp.StatusCode != 200 || !strings.Contains(string(b), "head") {
		t.Fatalf("GET after HEAD: %d %s", resp.StatusCode, b)
	}
}

func TestHeaders(t *testing.T) {
	for _, path := range []string{"/healthz", "/s/" + randomToken(), "/nowhere"} {
		resp, _ := do(t, http.MethodGet, path, nil, nil)
		h := resp.Header
		if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("Content-Security-Policy") == "" {
			t.Errorf("%s: missing headers %v", path, h)
		}
	}
}

// Runs last: drains the read bucket.
func TestZZRateLimitBurstAndSpoofedXFF(t *testing.T) {
	time.Sleep(1500 * time.Millisecond)
	burst := func(spoof bool) int {
		var wg sync.WaitGroup
		var mu sync.Mutex
		n := 0
		for i := range 250 {
			wg.Go(func() {
				hdr := map[string]string{}
				if spoof {
					hdr["X-Forwarded-For"] = fmt.Sprintf("203.0.113.%d", i%250)
					hdr["X-Real-IP"] = fmt.Sprintf("198.51.100.%d", i%250)
				}
				resp, _ := do(t, http.MethodGet, "/s/"+randomToken(), nil, hdr)
				if resp.StatusCode == http.StatusTooManyRequests {
					mu.Lock()
					n++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		return n
	}
	if n := burst(false); n == 0 {
		t.Fatal("burst of 250 reads got no 429")
	}
	time.Sleep(1500 * time.Millisecond)
	if n := burst(true); n == 0 {
		t.Fatal("spoofed X-Forwarded-For bypassed the rate limit")
	}
}
