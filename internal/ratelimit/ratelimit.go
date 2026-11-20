// Package ratelimit implements per-client token buckets held in process
// memory (ADR 0002). Clients are identified only by the TCP peer address;
// forwarding headers are never consulted.
package ratelimit

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const idleTTL = 5 * time.Minute

// Limiter is a set of token buckets keyed by client. A nil *Limiter allows everything.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   rate.Limit
	burst   int
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// New returns a Limiter, or nil (unlimited) when perSec <= 0.
func New(perSec float64, burst int) *Limiter {
	if perSec <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{buckets: map[string]*bucket{}, limit: rate.Limit(perSec), burst: burst}
}

// Allow reports whether the client identified by key may proceed now.
func (l *Limiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	l.mu.Unlock()
	return b.lim.AllowN(now, 1)
}

// Sweep drops buckets idle for longer than the idle TTL so the map cannot grow without bound.
func (l *Limiter) Sweep(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if now.Sub(b.seen) > idleTTL {
			delete(l.buckets, k)
		}
	}
}

// Len returns the number of tracked clients.
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// RunSweeper sweeps every minute until ctx is done.
func (l *Limiter) RunSweeper(ctx context.Context) {
	if l == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			l.Sweep(now)
		}
	}
}

// ClientIP returns the peer IP from an http.Request.RemoteAddr.
func ClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Key returns the rate-limit key for a peer address: the IPv4 address, or the
// /64 prefix for IPv6 so one host cannot rotate through its own block.
func Key(remoteAddr string) string {
	ip := ClientIP(remoteAddr)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		p, err := addr.Prefix(64)
		if err == nil {
			return p.String()
		}
	}
	return addr.String()
}
