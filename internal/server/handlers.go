package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"secret-sharing/internal/ratelimit"
	"secret-sharing/internal/seal"
	"secret-sharing/internal/sensitive"
	"secret-sharing/internal/store"
	"secret-sharing/internal/token"
)

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	ctx, ip := r.Context(), ratelimit.ClientIP(r.RemoteAddr)

	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCreateBody)).Decode(&req); err != nil {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "")
			return
		}
		field := "body"
		if ute := (*json.UnmarshalTypeError)(nil); errors.As(err, &ute) && ute.Field != "" {
			field = ute.Field
		}
		writeError(w, http.StatusBadRequest, "invalid_request", field)
		return
	}

	if req.Content == nil || *req.Content == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "content")
		return
	}
	content := sensitive.New(*req.Content)
	if content.Len() > maxContentBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "content")
		return
	}
	ttl := int64(defaultTTLSeconds)
	if req.TTLSeconds != nil {
		ttl = *req.TTLSeconds
	}
	if ttl < 1 || ttl > maxTTLSeconds {
		writeError(w, http.StatusBadRequest, "invalid_request", "ttl_seconds")
		return
	}
	maxViews := int64(defaultMaxViews)
	if req.MaxViews != nil {
		maxViews = *req.MaxViews
	}
	if maxViews < 1 || maxViews > maxMaxViews {
		writeError(w, http.StatusBadRequest, "invalid_request", "max_views")
		return
	}
	var passphrase []byte
	if req.Passphrase != nil && *req.Passphrase != "" {
		if len(*req.Passphrase) > maxPassphraseLen {
			writeError(w, http.StatusBadRequest, "invalid_request", "passphrase")
			return
		}
		passphrase = []byte(*req.Passphrase)
	}

	// Charged only once the request is known to be valid, and before any
	// sealing work: what is being rationed is space in the store.
	if !s.opts.CreateBytesLimiter.AllowN(ratelimit.Key(r.RemoteAddr), content.Len()) {
		s.tooMany(w, r, "/secrets", "stored_bytes")
		return
	}

	share := token.NewShare()
	deletionToken := token.NewDeletionToken()
	sealed, err := s.sealer.Seal(ctx, []byte(content.Reveal()), share.Key, share.LookupID, passphrase)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	ttlDur := time.Duration(ttl) * time.Second
	err = s.store.Create(ctx, share.LookupID, store.New{
		Sealed:        sealed,
		HasPassphrase: passphrase != nil,
		MaxViews:      int(maxViews),
		DeletionHash:  token.HashDeletionToken(deletionToken),
		TTL:           ttlDur,
	})
	if errors.Is(err, store.ErrFull) {
		writeError(w, http.StatusServiceUnavailable, "capacity", "")
		return
	}
	if err != nil {
		s.storeFailure(w)
		return
	}

	s.m.created.Inc()
	s.audit(ctx, "secret.created", ip, s.secretRef(share.LookupID),
		slog.Int64("ttl_seconds", ttl), slog.Int64("max_views", maxViews), slog.Bool("has_passphrase", passphrase != nil))
	link := s.opts.PublicBaseURL + "/s/" + share.Encode()
	writeJSON(w, http.StatusCreated, createResponse{
		ID:            share.Encode(),
		ShareURL:      link,
		URL:           link,
		DeletionToken: deletionToken,
		ExpiresAt:     time.Now().Add(ttlDur).UTC().Format(time.RFC3339),
	})
}

// handleRead: peek (reserving a Failed Unlock slot when a Passphrase is
// presented) → derive + open in the app → one atomic Lua call that either
// consumes a View (success) or records the Failed Unlock (auth failure).
// The slot is taken before any key derivation, so however many guesses arrive
// at once, at most MaxFailedUnlocks wrong ones are ever tried against a Secret.
// Every path that carries a Passphrase runs exactly one Argon2id, and every
// path makes exactly two Redis round trips, so outcomes are timing-equal.
func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	ctx, ip := r.Context(), ratelimit.ClientIP(r.RemoteAddr)
	share, ok := token.Parse(r.PathValue("token"))
	if !ok {
		share = token.Decoy() // walk the unknown-ID path, at the same cost
	}
	ref := s.secretRef(share.LookupID)
	pp := passphraseFrom(w, r)
	// Presenting a Passphrase always costs one Argon2id, even for a token that
	// matches nothing, so those reads get their own much smaller budget.
	if !pp.IsZero() && !s.opts.UnlockLimiter.Allow(ratelimit.Key(r.RemoteAddr)) {
		s.tooMany(w, r, "/s/:token", "unlocks")
		return
	}

	rec, found, err := s.store.Peek(ctx, share.LookupID, !pp.IsZero())
	if err != nil {
		s.storeFailure(w)
		return
	}
	if !found {
		if !pp.IsZero() {
			_ = s.sealer.Burn(ctx)
		}
		s.readGone(ctx, w, ip, ref, true)
		return
	}
	if rec.HasPassphrase && pp.IsZero() {
		_ = s.store.Noop(ctx)
		writeError(w, http.StatusUnauthorized, "passphrase_required", "")
		return
	}
	if rec.HasPassphrase && !rec.Reserved {
		// Every remaining Failed Unlock slot is held by an attempt still in
		// flight. This Passphrase is not tried at all, so the answer cannot
		// depend on it; it costs the same as a wrong guess.
		_ = s.sealer.Burn(ctx)
		_ = s.store.Noop(ctx)
		s.audit(ctx, "secret.unlock_rejected", ip, ref)
		writeError(w, http.StatusUnauthorized, "passphrase_required", "")
		return
	}

	var passphrase []byte
	switch {
	case rec.HasPassphrase:
		passphrase = []byte(pp.Reveal())
	case !pp.IsZero():
		_ = s.sealer.Burn(ctx) // a Passphrase was sent: pay for one Argon2id like every other such path
	}

	content, err := s.sealer.Open(ctx, rec.Sealed, share.Key, share.LookupID, passphrase)
	if errors.Is(err, seal.ErrAuth) {
		if !rec.HasPassphrase { // wrong Secret Key: the caller does not hold a valid link
			s.readGone(ctx, w, ip, ref, true)
			return
		}
		s.failUnlock(ctx, w, ip, ref, share.LookupID)
		return
	}
	if err != nil {
		if rec.Reserved {
			// The attempt was abandoned before it could be judged (the client
			// went away while queued for the KDF). Fail closed: it keeps its
			// slot as a Failed Unlock rather than leaking the reservation.
			_, _, _, _ = s.store.FailUnlock(context.WithoutCancel(ctx), share.LookupID)
		}
		writeError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	defer clear(content)

	left, granted, err := s.store.Consume(ctx, share.LookupID, rec.Reserved)
	if err != nil {
		s.storeFailure(w)
		return
	}
	if !granted { // Revoked, expired or out of Views between peek and consume
		s.readGone(ctx, w, ip, ref, false)
		return
	}
	s.m.views.Inc()
	s.audit(ctx, "secret.viewed", ip, ref, slog.Int("views_left", left))
	writeJSON(w, http.StatusOK, struct {
		Content string `json:"content"`
	}{Content: string(content)})
}

func (s *Server) failUnlock(ctx context.Context, w http.ResponseWriter, ip, ref string, lookupID []byte) {
	failed, destroyed, found, err := s.store.FailUnlock(ctx, lookupID)
	if err != nil {
		s.storeFailure(w)
		return
	}
	if !found {
		// Gone between peek and here. Answer exactly as a right Passphrase
		// would at this point, so the status never says which one it was.
		s.readGone(ctx, w, ip, ref, false)
		return
	}
	s.m.failedUnlocks.Inc()
	s.audit(ctx, "secret.unlock_failed", ip, ref, slog.Int("failed_unlocks", failed))
	if destroyed {
		s.m.destroyed.Inc()
		s.audit(ctx, "secret.destroyed", ip, ref, slog.String("reason", "failed_unlocks"))
	}
	writeError(w, http.StatusUnauthorized, "passphrase_required", "")
}

// readGone answers 404. padRoundTrip adds the second Redis round trip on paths
// that have not made one yet.
func (s *Server) readGone(ctx context.Context, w http.ResponseWriter, ip, ref string, padRoundTrip bool) {
	if padRoundTrip {
		_ = s.store.Noop(ctx)
	}
	s.m.goneReads.Inc()
	s.audit(ctx, "secret.read_gone", ip, ref)
	writeError(w, http.StatusNotFound, "not_found", "")
}

// handleRevoke: a wrong Deletion Token and a Gone Secret are indistinguishable (both 404, same work).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx, ip := r.Context(), ratelimit.ClientIP(r.RemoteAddr)
	share, ok := token.Parse(r.PathValue("token"))
	if !ok {
		share = token.Decoy()
	}
	ref := s.secretRef(share.LookupID)
	presented := token.HashDeletionToken(deletionTokenFrom(w, r).Reveal())

	stored, found, err := s.store.DeletionHash(ctx, share.LookupID)
	if err != nil {
		s.storeFailure(w)
		return
	}
	if !found {
		stored = make([]byte, len(presented))
	}
	match := subtle.ConstantTimeCompare(stored, presented) == 1 && found

	if !match {
		_ = s.store.Noop(ctx)
		s.audit(ctx, "secret.revoke_denied", ip, ref)
		writeError(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err := s.store.Delete(ctx, share.LookupID); err != nil {
		s.storeFailure(w)
		return
	}
	s.m.revocations.Inc()
	s.audit(ctx, "secret.revoked", ip, ref)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) storeFailure(w http.ResponseWriter) {
	s.m.storeErrors.Inc()
	writeError(w, http.StatusServiceUnavailable, "unavailable", "")
}
