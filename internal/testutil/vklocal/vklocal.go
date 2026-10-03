// Package vklocal points tests at a local Valkey named by
// RELAY_TEST_VALKEY_ADDR (host:port; see `make test-dynamo`). Tests that
// need it are skipped when the variable is unset.
package vklocal

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

// EnvAddr names the Valkey address for tests.
const EnvAddr = "RELAY_TEST_VALKEY_ADDR"

// Addr returns the test Valkey address, skipping t if none is set.
func Addr(t testing.TB) string {
	t.Helper()
	a := os.Getenv(EnvAddr)
	if a == "" {
		t.Skipf("%s not set (run `make test-dynamo`)", EnvAddr)
	}
	return a
}

// Prefix returns a fresh key prefix so tests sharing one Valkey never see
// each other's keys or channels.
func Prefix() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "t" + hex.EncodeToString(b)
}
