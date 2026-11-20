package token

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestShareRoundTrip(t *testing.T) {
	s := NewShare()
	enc := s.Encode()
	if len(enc) != EncodedLen {
		t.Fatalf("len %d", len(enc))
	}
	got, ok := Parse(enc)
	if !ok || string(got.LookupID) != string(s.LookupID) || string(got.Key) != string(s.Key) {
		t.Fatal("round trip failed")
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "abc", strings.Repeat("A", 63), strings.Repeat("A", 65), strings.Repeat("+", 64), strings.Repeat("=", 64)} {
		if _, ok := Parse(in); ok {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestShareRedacts(t *testing.T) {
	s := NewShare()
	j, _ := json.Marshal(s)
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), string(j)} {
		if strings.Contains(out, s.Encode()) || !strings.Contains(out, "REDACTED") {
			t.Errorf("leaked: %s", out)
		}
	}
}

func TestDeletionTokensIndependent(t *testing.T) {
	a, b := NewDeletionToken(), NewDeletionToken()
	if a == b || len(a) != 43 {
		t.Fatalf("bad tokens %d", len(a))
	}
	if string(HashDeletionToken(a)) == a {
		t.Fatal("hash is identity")
	}
}
