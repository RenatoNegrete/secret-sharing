package server

import (
	"log/slog"
	"net/http"
	"time"

	"secret-sharing/internal/ratelimit"
)

// securityHeaders sets the transport headers on every response, errors included.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// recoverer replaces net/http's panic logging, which would print the panic
// value (possibly request data). It logs a fixed message only.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { // net/http's own sentinel for an intentional abort
					panic(v)
				}
				s.log.LogAttrs(r.Context(), slog.LevelError, "http.panic",
					slog.String("event", "http.panic"), slog.String("method", r.Method))
				writeError(w, http.StatusInternalServerError, "internal", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// instrument records latency metrics and the request log line under a fixed
// route template — never the raw path, query string or headers.
func (s *Server) instrument(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		d := time.Since(start)
		s.m.duration.WithLabelValues(route, r.Method, statusClass(sw.code)).Observe(d.Seconds())
		if route == "/metrics" || route == "/healthz" {
			return
		}
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "http.request",
			slog.String("event", "http.request"),
			slog.String("ip", ratelimit.ClientIP(r.RemoteAddr)),
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", sw.code),
			slog.Float64("duration_ms", float64(d.Microseconds())/1000),
		)
	})
}

// limit applies a per-client token bucket keyed only on the TCP peer address.
func (s *Server) limit(route string, l *ratelimit.Limiter, next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(ratelimit.Key(r.RemoteAddr)) {
			s.m.rateLimited.WithLabelValues(route).Inc()
			s.audit(r.Context(), "rate_limited", ratelimit.ClientIP(r.RemoteAddr), "", slog.String("route", route))
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code    int
	written bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.written {
		w.code, w.written = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
