// Package paircode is the relay's part of the short pairing codes' crypto
// (RELAY-PROTOCOL 0.14.1 §6.9.1, VAULT-MESSAGING 0.94.1 §6.7.2): the
// relay's canonical base URL r, the hourly lookup salts and the window in
// which each is listed, and the keyed MAC under which a code claim is
// stored. The relay never sees a code; it sees an Argon2id tag of one, and
// stores only HMAC-SHA-256(k_pc, tag).
//
// Tags, code_macs and k_pc are never logged.
package paircode

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Hour is an epoch's length in seconds: epoch = floor(unix time / 3600).
	Hour = 3600
	// NonceSize and SaltSize are the nonce's and s_r's sizes; TagSize is a
	// tag's, MACSize a code_mac's, KeySize k_pc's.
	NonceSize = 16
	SaltSize  = 16
	TagSize   = 32
	MACSize   = 32
	KeySize   = 32
	// ListedEarly and ListedLate: the next epoch's salt is listed from
	// ListedEarly before it starts, the previous one's until ListedLate
	// after it ends (§6.9.1).
	ListedEarly = 2 * time.Minute
	ListedLate  = 10 * time.Minute

	labelSalt  = "vettid/pair-code/1/salt"
	labelKeyID = "vettid/pair-code/1/key-id"
)

// ErrRelay is a base URL that has no canonical form.
var ErrRelay = errors.New("paircode: not a canonical relay base URL")

// CanonicalRelay returns the canonical form of a relay's base URL
// (VAULT-MESSAGING §6.7.2 "The relay's base URL"): `https://`, the host in
// lower case, then `:port` only when it is not 443, with no path and no
// trailing slash. A bare host or host:port gets `https://`. It refuses a
// path, a query, a fragment, user information, an IP literal, a
// non-ASCII host (an internationalized name only in its xn-- form) and any
// scheme other than https. A lone trailing "/" is the empty path.
// (The vault's vms/paircode has the same function; the shared vectors
// test both.)
func CanonicalRelay(s string) (string, error) {
	if s == "" || len(s) > 2048 || strings.ContainsAny(s, " \t\r\n\\") {
		return "", ErrRelay
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.Contains(s, "#") || strings.ToLower(u.Scheme) != "https" {
		return "", ErrRelay
	}
	if u.Path != "" && u.Path != "/" || u.RawPath != "" {
		return "", ErrRelay
	}
	host, port := u.Hostname(), u.Port()
	if strings.HasPrefix(u.Host, "[") || net.ParseIP(host) != nil || !dnsName(host) {
		return "", ErrRelay
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrRelay
	}
	out := "https://" + strings.ToLower(host)
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", ErrRelay
		}
		if n != 443 {
			out += ":" + port
		}
	}
	return out, nil
}

// dnsName reports whether h is a DNS name in ASCII: labels of letters,
// digits and hyphens, 1 to 63 bytes, not starting or ending with a hyphen,
// at most 253 bytes, and a last label that is not a number (which URL
// parsers read as an IPv4 address: 127.1, 0x7f.1, 1.0x).
func dnsName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return !numericLabel(labels[len(labels)-1])
}

// numericLabel reports a label a WHATWG host parser reads as a number:
// all decimal digits, or 0x / 0X followed by zero or more hex digits.
func numericLabel(l string) bool {
	digits := l
	hexa := len(l) >= 2 && (l[:2] == "0x" || l[:2] == "0X")
	if hexa {
		digits = l[2:]
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if !(c >= '0' && c <= '9' || hexa && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Epoch returns the hour of t.
func Epoch(t time.Time) int64 {
	u := t.Unix()
	q := u / Hour
	if u%Hour != 0 && u < 0 {
		q--
	}
	return q
}

// Start returns the time epoch begins.
func Start(epoch int64) time.Time { return time.Unix(epoch*Hour, 0).UTC() }

// Listed returns the epochs whose salts the relay lists at now, in
// ascending order: the current one, the next from ListedEarly before it
// starts, the previous until ListedLate after it ended. The windows never
// overlap, so there are 1 or 2.
func Listed(now time.Time) []int64 {
	e := Epoch(now)
	switch {
	case !now.Before(Start(e + 1).Add(-ListedEarly)):
		return []int64{e, e + 1}
	case now.Before(Start(e).Add(ListedLate)):
		return []int64{e - 1, e}
	}
	return []int64{e}
}

// Creatable returns the epochs a new code claim may name at now (§6.9.1
// creating step 3): the current one, and the next once it is listed;
// never the previous.
func Creatable(now time.Time) []int64 {
	l := Listed(now)
	if len(l) == 2 && l[0] < Epoch(now) {
		return l[1:]
	}
	return l
}

// SaltR returns an hour's lookup salt: the first 16 bytes of
// SHA-256("vettid/pair-code/1/salt" || 0x00 || r || 0x00 || epoch (8
// bytes, big-endian) || 0x00 || nonce).
func SaltR(r string, epoch int64, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelSalt))
	h.Write([]byte{0})
	h.Write([]byte(r))
	h.Write([]byte{0})
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(epoch))
	h.Write(e[:])
	h.Write([]byte{0})
	h.Write(nonce)
	return h.Sum(nil)[:SaltSize]
}

// SaltID returns the lowercase hex of s_r's first 4 bytes.
func SaltID(sr []byte) string { return hex.EncodeToString(sr[:4]) }

// MAC returns code_mac = HMAC-SHA-256(k, tag).
func MAC(k, tag []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write(tag)
	return m.Sum(nil)
}

// KeyID names k without revealing it: the lowercase hex of the first 8
// bytes of HMAC-SHA-256(k, "vettid/pair-code/1/key-id") (chosen; not in
// the spec). Code claims are filed under it, so a rotated k_pc leaves
// every older claim unredeemable at once.
func KeyID(k []byte) string { return hex.EncodeToString(MAC(k, []byte(labelKeyID))[:8]) }
