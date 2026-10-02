package auth

import (
	"strings"
	"testing"
)

func TestClaimID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewClaimID()
		if len(id) != ClaimIDLen || id != strings.ToLower(id) || seen[id] {
			t.Fatalf("bad or repeated id %q", id)
		}
		seen[id] = true
		if _, ok := ParseClaimID(id); !ok {
			t.Fatalf("own id rejected: %q", id)
		}
	}
	good := NewClaimID()
	for _, bad := range []string{
		"", strings.ToUpper(good), good[:25], good + "a", good[:25] + "1", good[:25] + "8",
		good[:10] + "=" + good[11:], strings.Repeat("a", 25) + "b", // trailing bits set
	} {
		if _, ok := ParseClaimID(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, ok := ParseClaimID(strings.Repeat("a", 25) + "a"); !ok {
		t.Error("all-zero id rejected")
	}
}

func FuzzParseClaimID(f *testing.F) {
	f.Add(NewClaimID())
	f.Add(strings.Repeat("a", 26))
	f.Add(strings.Repeat("7", 26))
	f.Add("")
	f.Add("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	f.Fuzz(func(t *testing.T, s string) {
		b, ok := ParseClaimID(s)
		if !ok {
			return
		}
		// Accepted ids are canonical: exactly one spelling per 128-bit value.
		if strings.ToLower(claimEncoding.EncodeToString(b[:])) != s || len(s) != ClaimIDLen {
			t.Fatalf("non-canonical id accepted: %q", s)
		}
	})
}
