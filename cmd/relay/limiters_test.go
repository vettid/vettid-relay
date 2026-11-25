package main

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/coord"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/testutil/vklocal"
)

// Limit 14 (code redeems) is wired to Valkey: two relay processes on one
// Valkey draw on one budget.
func TestCodeRedeemLimitIsShared(t *testing.T) {
	addr := vklocal.Addr(t)
	prefix := vklocal.Prefix()
	open := func() *coord.Client {
		vc, err := coord.Open(context.Background(), coord.Config{Addr: addr, Prefix: prefix}, metrics.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { vc.Close() })
		return vc
	}
	cfg := config.Defaults()
	a, b := sharedLimiters(open(), cfg), sharedLimiters(open(), cfg)
	if a.CodeRedeem == nil || b.CodeRedeem == nil {
		t.Fatal("limit 14 isn't wired to the shared limiters")
	}
	la, lb := a.CodeRedeem("code_redeem", 1e-6, 2), b.CodeRedeem("code_redeem", 1e-6, 2)
	now := time.Now()
	for i := range 2 {
		if ok, _ := la.AllowN("192.0.2.1", 1, now); !ok {
			t.Fatalf("refused at %d of 2", i)
		}
	}
	if ok, _ := lb.AllowN("192.0.2.1", 1, now); ok {
		t.Fatal("the other process has a budget of its own: limit 14 isn't relay-wide")
	}
	if ok, _ := lb.AllowN("192.0.2.2", 1, now); !ok {
		t.Fatal("another address shares the budget")
	}
}
