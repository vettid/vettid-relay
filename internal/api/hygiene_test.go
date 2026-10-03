package api

import (
	"bytes"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Spec §8.2 / plan working agreements: logs carry msg ids, sizes and codes
// only — never payloads, tokens, signatures, full pubkeys or mailbox ids.
func TestLogsCarryNoSecretsOrPayloads(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, nil, &logs)
	owner, sender, mallory := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	payload := []byte("TOP-SECRET-CIPHERTEXT-MARKER")
	id := f.mustDeposit(owner, sender, tok, payload)
	f.collect(owner, "")
	f.ack(owner, id)
	blob := []byte("BLOB-CIPHERTEXT-MARKER")
	f.mustPutBlob(owner, sender, tok, blob)
	f.do(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody(payload), signer: &mallory, token: tok})
	f.do(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody(payload), signer: &sender, token: "v4.public.garbage"})
	f.revoke(owner, "sub", mallory.b64)
	claimBody := []byte("CLAIM-BUNDLE-MARKER")
	claim := f.mustPutClaim(owner, claimBody, "")
	f.getClaim(claim.ClaimID, nil)
	f.getClaim(claim.ClaimID, nil)
	unfetched := f.mustPutClaim(owner, claimBody, "")
	f.do(req{method: "DELETE", path: "/v1/claim/" + unfetched.ClaimID, signer: &owner})
	openTok := f.mintOpen(owner, "hygiene-open", time.Minute)
	f.mustDeposit(owner, mallory, openTok, []byte("x"))

	out := logs.String()
	if !strings.Contains(out, id) || !strings.Contains(out, `"code":"signature_invalid"`) {
		t.Fatalf("expected msg ids and codes in logs:\n%s", out)
	}
	hr := f.build(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody(payload), signer: &sender, token: tok})
	for name, secret := range map[string]string{
		"payload":         string(payload),
		"payload b64":     base64.StdEncoding.EncodeToString(payload),
		"blob":            string(blob),
		"blob b64":        base64.StdEncoding.EncodeToString(blob),
		"token":           tok,
		"token body":      tok[len("v4.public.") : len("v4.public.")+40],
		"owner pubkey":    owner.b64,
		"sender pubkey":   sender.b64,
		"mallory pubkey":  mallory.b64,
		"owner mailbox":   owner.mbx,
		"claim id":        claim.ClaimID,
		"claim id 2":      unfetched.ClaimID,
		"claim body":      string(claimBody),
		"open token":      openTok,
		"sig header name": auth.HeaderSig,
		"a signature":     hr.Header.Get(auth.HeaderSig)[:40],
	} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain %s", name)
		}
	}
}

func TestMetricsExposition(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	f.collect(owner, "")
	var b strings.Builder
	f.reg.WriteTo(&b)
	for _, want := range []string{
		"relay_deposits_total 1", "relay_registrations_total 1", "relay_collected_messages_total 1",
		`relay_errors_total{code="token_invalid"} 0`, "relay_parked_collectors 0", "relay_replay_cache_entries ",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if strings.Contains(b.String(), owner.mbx) {
		t.Error("metrics leak mailbox ids")
	}
}

// Long-polls that end empty (most traffic with always-on collectors) log at
// debug; a collect that delivers logs at info.
func TestEmptyCollectLogsAtDebug(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, nil, &logs)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.collect(owner, "")
	f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	f.collect(owner, "")
	var levels []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `"route":"GET /v1/mailbox"`) {
			switch {
			case strings.Contains(line, `"level":"DEBUG"`) && strings.Contains(line, `"count":0`):
				levels = append(levels, "debug-empty")
			case strings.Contains(line, `"level":"INFO"`) && strings.Contains(line, `"count":1`):
				levels = append(levels, "info-delivered")
			default:
				levels = append(levels, line)
			}
		}
	}
	if strings.Join(levels, ",") != "debug-empty,info-delivered" {
		t.Fatalf("collect log levels: %v", levels)
	}
}
