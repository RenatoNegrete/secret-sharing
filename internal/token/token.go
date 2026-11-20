// Package token creates and parses Share Tokens and Deletion Tokens.
//
// A Share Token is base64url(LookupID ‖ SecretKey) without padding: 16 + 32
// raw bytes, always exactly 64 characters. The Lookup ID locates a stored
// Secret; the Secret Key unlocks it and exists nowhere but in the token.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
)

const (
	LookupIDLen = 16
	KeyLen      = 32
	EncodedLen  = 64 // base64url of 48 bytes, no padding

	deletionTokenLen = 32
)

const redacted = "[REDACTED]"

var enc = base64.RawURLEncoding.Strict()

// Share is a parsed Share Token. It redacts itself in every formatting path.
type Share struct {
	LookupID []byte
	Key      []byte
}

// NewShare draws a fresh random Lookup ID and Secret Key.
func NewShare() Share {
	buf := make([]byte, LookupIDLen+KeyLen)
	_, _ = rand.Read(buf) // crypto/rand.Read never fails since Go 1.24; it aborts the process instead
	return Share{LookupID: buf[:LookupIDLen], Key: buf[LookupIDLen:]}
}

// Decoy returns a Share with a random Lookup ID that will not exist in
// storage. Malformed tokens are replaced by a decoy so they walk the exact
// same not-found path (and cost) as an unknown token.
func Decoy() Share { return NewShare() }

// Parse decodes a Share Token. It returns false for anything that is not
// exactly 64 strict base64url characters.
func Parse(s string) (Share, bool) {
	if len(s) != EncodedLen {
		return Share{}, false
	}
	raw, err := enc.DecodeString(s)
	if err != nil || len(raw) != LookupIDLen+KeyLen {
		return Share{}, false
	}
	return Share{LookupID: raw[:LookupIDLen], Key: raw[LookupIDLen:]}, true
}

// Encode returns the token's wire form. Only call it to build the creator's response.
func (s Share) Encode() string {
	buf := make([]byte, 0, LookupIDLen+KeyLen)
	buf = append(buf, s.LookupID...)
	buf = append(buf, s.Key...)
	return enc.EncodeToString(buf)
}

func (Share) String() string               { return redacted }
func (Share) GoString() string             { return redacted }
func (Share) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Share) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Share) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }

// NewDeletionToken draws a 256-bit Deletion Token, independent of any Share Token.
func NewDeletionToken() string {
	buf := make([]byte, deletionTokenLen)
	_, _ = rand.Read(buf)
	return enc.EncodeToString(buf)
}

// HashDeletionToken is what storage keeps instead of the Deletion Token. A
// fast hash is sufficient: the token is 256 random bits, not a password.
func HashDeletionToken(t string) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}
