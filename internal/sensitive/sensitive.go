// Package sensitive wraps values that must never reach logs, metrics, errors
// or serialised output: Secret content, Passphrases, Share Tokens and
// Deletion Tokens. Every formatting path returns a fixed redaction marker;
// the raw value is only reachable through Reveal.
package sensitive

import (
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// String is a string that redacts itself everywhere except Reveal.
type String struct{ v string }

// New wraps s.
func New(s string) String { return String{v: s} }

// Reveal returns the raw value. Call it only at the point of use.
func (s String) Reveal() string { return s.v }

// IsZero reports whether no value was provided.
func (s String) IsZero() bool { return s.v == "" }

// Len returns the length of the raw value in bytes.
func (s String) Len() int { return len(s.v) }

func (String) String() string               { return redacted }
func (String) GoString() string             { return redacted }
func (String) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (String) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (String) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (String) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
