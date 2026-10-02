package api

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The code → HTTP status mapping must match the spec's §7.1 table exactly,
// and the relay must know every code the table lists (and no others).
func TestErrorTableMatchesSpec(t *testing.T) {
	f, err := os.Open("../../docs/RELAY-PROTOCOL.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	row := regexp.MustCompile("^\\| `([a-z_]+)` \\| (\\d{3}) \\|")
	spec := map[string]int{}
	in71 := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "### ") {
			in71 = strings.HasPrefix(line, "### 7.1")
		}
		if m := row.FindStringSubmatch(line); in71 && m != nil {
			spec[m[1]], _ = strconv.Atoi(m[2])
		}
	}
	if len(spec) < 16 {
		t.Fatalf("parsed only %d codes from §7.1", len(spec))
	}
	known := map[string]bool{}
	for _, c := range allCodes {
		known[c] = true
		want, ok := spec[c]
		if !ok {
			t.Errorf("relay code %q is not in the spec table", c)
			continue
		}
		if got := statusFor(c); got != want {
			t.Errorf("%s: status %d, spec says %d", c, got, want)
		}
		if defaultMessages[c] == "" {
			t.Errorf("%s: no message", c)
		}
	}
	for c := range spec {
		if !known[c] {
			t.Errorf("spec code %q not implemented", c)
		}
	}
}
