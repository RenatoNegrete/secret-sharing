// Package server is the HTTP API: routing, middleware, handlers, audit log.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"secret-sharing/internal/ratelimit"
	"secret-sharing/internal/seal"
	"secret-sharing/internal/store"
)

// Store is what the handlers need from storage. *store.Store implements it.
type Store interface {
	Create(ctx context.Context, lookupID []byte, n store.New) error
	Peek(ctx context.Context, lookupID []byte) (store.Record, bool, error)
	Consume(ctx context.Context, lookupID []byte) (int, bool, error)
	FailUnlock(ctx context.Context, lookupID []byte) (int, bool, error)
	Noop(ctx context.Context) error
	DeletionHash(ctx context.Context, lookupID []byte) ([]byte, bool, error)
	Delete(ctx context.Context, lookupID []byte) error
	Ping(ctx context.Context) error
}

// Options configures a Server.
type Options struct {
	PublicBaseURL string
	KDF           seal.Params
	CreateLimiter *ratelimit.Limiter
	ReadLimiter   *ratelimit.Limiter
}

// Server serves the API.
type Server struct {
	store   Store
	sealer  *seal.Sealer
	log     *slog.Logger
	m       *metrics
	opts    Options
	refKey  []byte
	handler http.Handler
}

// New builds a Server and its routes.
func New(st Store, log *slog.Logger, opts Options) (*Server, error) {
	s := &Server{store: st, log: log, m: newMetrics(), opts: opts, refKey: make([]byte, 32)}
	_, _ = rand.Read(s.refKey)
	sealer, err := seal.New(opts.KDF, func(d time.Duration) { s.m.kdfWait.Observe(d.Seconds()) })
	if err != nil {
		return nil, err
	}
	s.sealer = sealer
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux() // never http.DefaultServeMux: imported pprof would register itself there
	route := func(pattern, name string, lim *ratelimit.Limiter, h http.HandlerFunc) {
		mux.Handle(pattern, s.instrument(name, s.limit(name, lim, h)))
	}
	route("POST /secrets", "/secrets", s.opts.CreateLimiter, s.handleCreate)
	route("GET /s/{token}", "/s/:token", s.opts.ReadLimiter, s.handleRead)
	route("DELETE /s/{token}", "/s/:token", s.opts.ReadLimiter, s.handleRevoke)
	route("GET /healthz", "/healthz", nil, s.handleHealth)
	mux.Handle("GET /metrics", s.instrument("/metrics", s.m.handler()))
	mux.Handle("/", s.instrument("unmatched", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "")
	})))
	return s.recoverer(securityHeaders(mux))
}

// secretRef is the one-way, per-process alias for a Secret used in the audit log.
func (s *Server) secretRef(lookupID []byte) string {
	mac := hmac.New(sha256.New, s.refKey)
	mac.Write(lookupID)
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

// audit writes one audit event. Callers pass only non-sensitive attributes.
func (s *Server) audit(ctx context.Context, event, ip, ref string, attrs ...slog.Attr) {
	base := []slog.Attr{slog.String("event", event), slog.String("ip", ip)}
	if ref != "" {
		base = append(base, slog.String("secret_ref", ref))
	}
	s.log.LogAttrs(ctx, slog.LevelInfo, event, append(base, attrs...)...)
}
