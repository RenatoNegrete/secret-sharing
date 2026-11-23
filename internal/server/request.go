package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"secret-sharing/internal/config"
	"secret-sharing/internal/sensitive"
)

const (
	maxCreateBody     = 100 << 10 // 100 KB
	maxSideBody       = 8 << 10   // a GET/DELETE body only ever carries one short field
	maxContentBytes   = config.MaxContentBytes
	maxPassphraseLen  = 256
	defaultTTLSeconds = 86400
	maxTTLSeconds     = 604800
	defaultMaxViews   = 1
	maxMaxViews       = 100
)

type createRequest struct {
	Content    *string `json:"content"`
	TTLSeconds *int64  `json:"ttl_seconds"`
	MaxViews   *int64  `json:"max_views"`
	Passphrase *string `json:"passphrase"`
}

type createResponse struct {
	ID            string `json:"id"`
	ShareURL      string `json:"share_url"`
	URL           string `json:"url"`
	DeletionToken string `json:"deletion_token"`
	ExpiresAt     string `json:"expires_at"`
}

// passphraseFrom reads an optional Passphrase from a read request, in order:
// X-Passphrase header, JSON body, ?passphrase= query. None of these is ever logged.
func passphraseFrom(w http.ResponseWriter, r *http.Request) sensitive.String {
	if v := r.Header.Get("X-Passphrase"); v != "" {
		return sensitive.New(v)
	}
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if readSideBody(w, r, &body) && body.Passphrase != "" {
		return sensitive.New(body.Passphrase)
	}
	return sensitive.New(r.URL.Query().Get("passphrase"))
}

// deletionTokenFrom reads the Deletion Token, in order: Authorization: Bearer,
// X-Deletion-Token header, JSON body, ?deletion_token= query.
func deletionTokenFrom(w http.ResponseWriter, r *http.Request) sensitive.String {
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return sensitive.New(strings.TrimSpace(a[7:]))
	}
	if v := r.Header.Get("X-Deletion-Token"); v != "" {
		return sensitive.New(v)
	}
	var body struct {
		DeletionToken string `json:"deletion_token"`
	}
	if readSideBody(w, r, &body) && body.DeletionToken != "" {
		return sensitive.New(body.DeletionToken)
	}
	return sensitive.New(r.URL.Query().Get("deletion_token"))
}

// readSideBody decodes a small optional JSON body on GET/DELETE. Any failure
// just means "no value in the body".
func readSideBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSideBody))
	if err != nil || len(data) == 0 {
		return false
	}
	return json.Unmarshal(data, dst) == nil
}

type errorBody struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

// writeError writes a fixed error body. It names a field but never echoes a value.
func writeError(w http.ResponseWriter, status int, code, field string) {
	writeJSON(w, status, errorBody{Error: code, Field: field})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
