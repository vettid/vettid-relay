package relayclient

import (
	"encoding/json"
	"testing"
	"time"
)

// The tombstone report is read as RELAY-PROTOCOL 0.12.0 §6.1 says: only
// with the flag true; a field without it, or one that can't be parsed,
// counts as neither; a fractional second is rounded up.
func TestRegistrationTombstone(t *testing.T) {
	at := time.Date(2026, 11, 14, 15, 1, 30, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		body     string
		want     time.Time
		reported bool
	}{
		{"no flag", `{"mailbox_id":"m","limits":{}}`, time.Time{}, false},
		{"no flag, a field", `{"mailbox_id":"m","limits":{},"tokens_not_before":"2026-11-14T15:01:30Z"}`, time.Time{}, false},
		{"flag false", `{"limits":{"reports_tombstones":false},"tokens_not_before":"2026-11-14T15:01:30Z"}`, time.Time{}, false},
		{"flag not a bool", `{"limits":{"reports_tombstones":"true"},"tokens_not_before":"2026-11-14T15:01:30Z"}`, time.Time{}, false},
		{"flag, no field", `{"limits":{"reports_tombstones":true}}`, time.Time{}, true},
		{"flag and field", `{"limits":{"reports_tombstones":true},"tokens_not_before":"2026-11-14T15:01:30Z"}`, at, true},
		{"a fractional second", `{"limits":{"reports_tombstones":true},"tokens_not_before":"2026-11-14T15:01:29.2Z"}`, at, true},
		{"an offset", `{"limits":{"reports_tombstones":true},"tokens_not_before":"2026-11-14T16:01:30+01:00"}`, at, true},
		{"unparseable", `{"limits":{"reports_tombstones":true},"tokens_not_before":"soon"}`, time.Time{}, false},
		{"not a string", `{"limits":{"reports_tombstones":true},"tokens_not_before":1793000000}`, time.Time{}, false},
	} {
		var r Registration
		if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, reported := r.Tombstone()
		if reported != tc.reported || !got.Equal(tc.want) {
			t.Errorf("%s: %v %v, want %v %v", tc.name, got, reported, tc.want, tc.reported)
		}
	}
}
