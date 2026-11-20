package seal

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func newTestSealer(t *testing.T) *Sealer {
	t.Helper()
	s, err := New(Params{ArgonTime: 1, ArgonMemoryKiB: 8 * 1024}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s, ctx := newTestSealer(t), context.Background()
	key, id := randBytes(32), randBytes(16)
	for _, pp := range [][]byte{nil, []byte("hunter2")} {
		sealed, err := s.Seal(ctx, []byte("secret"), key, id, pp)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed.Ciphertext, []byte("secret")) {
			t.Fatal("plaintext visible in ciphertext")
		}
		pt, err := s.Open(ctx, sealed, key, id, pp)
		if err != nil || string(pt) != "secret" {
			t.Fatalf("open: %v %q", err, pt)
		}
	}
}

func TestAuthFailures(t *testing.T) {
	s, ctx := newTestSealer(t), context.Background()
	key, id := randBytes(32), randBytes(16)
	sealed, err := s.Seal(ctx, []byte("secret"), key, id, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"wrong passphrase": func() error { _, e := s.Open(ctx, sealed, key, id, []byte("wrong")); return e },
		"no passphrase":    func() error { _, e := s.Open(ctx, sealed, key, id, nil); return e },
		"wrong key":        func() error { _, e := s.Open(ctx, sealed, randBytes(32), id, []byte("right")); return e },
		"swapped id (AAD)": func() error { _, e := s.Open(ctx, sealed, key, randBytes(16), []byte("right")); return e },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: want ErrAuth, got %v", name, err)
		}
	}
}

func TestBurn(t *testing.T) {
	if err := newTestSealer(t).Burn(context.Background()); err != nil {
		t.Fatal(err)
	}
}
