package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	l := New(1, 3)
	for i := range 3 {
		if !l.Allow("a") {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th request allowed")
	}
	if !l.Allow("b") {
		t.Fatal("other client affected")
	}
}

func TestNilIsUnlimited(t *testing.T) {
	var l *Limiter = New(0, 0)
	for range 1000 {
		if !l.Allow("a") {
			t.Fatal("nil limiter denied")
		}
	}
}

func TestSweep(t *testing.T) {
	l := New(1, 1)
	l.Allow("a")
	l.Sweep(time.Now().Add(idleTTL + time.Second))
	if l.Len() != 0 {
		t.Fatal("idle bucket not swept")
	}
}

func TestKey(t *testing.T) {
	cases := map[string]string{
		"10.1.2.3:4444":              "10.1.2.3",
		"[2001:db8:1:2:aaaa::1]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb::9]:443": "2001:db8:1:2::/64",
		"[::ffff:192.0.2.7]:80":      "192.0.2.7",
	}
	for in, want := range cases {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}
