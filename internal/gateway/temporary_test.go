package gateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// temporaryDevice is a live temporary install with the given deadline.
func temporaryDevice(id, host string, lastSeen, expiresAt time.Time) model.Device {
	d := device(id, "acme", host, "windows", lastSeen)
	d.Ephemeral, d.ExpiresAt = true, &expiresAt
	return d
}

// TestExpiredTemporaryDeviceIsRefused covers the window between a temporary
// session's deadline and the relay's next reconcile: the store still has the
// device enrolled, and the gateway must already treat it as gone. Otherwise a
// late sweep would silently extend a session the customer consented to for an
// hour.
func TestExpiredTemporaryDeviceIsRefused(t *testing.T) {
	f := newFixture(t)
	now := f.now
	recent := now.Add(-10 * time.Second)
	f.dir.devices["acme"] = append(f.dir.devices["acme"],
		temporaryDevice("dev_acme_temp_live", "TEMP-LIVE", recent, now.Add(30*time.Minute)),
		temporaryDevice("dev_acme_temp_over", "TEMP-OVER", recent, now.Add(-time.Minute)),
	)
	cs := f.connect(t, bearerACME)

	t.Run("an expired session is denied like a revoked device", func(t *testing.T) {
		text, isErr := call(t, cs, proto.OpStat, map[string]any{"device": "dev_acme_temp_over", "path": cbsLog})
		if !isErr || !strings.HasPrefix(text, proto.ErrDeviceRevoked+": ") {
			t.Fatalf("expired temporary device answered %q", text)
		}
		if e := f.lastEntry(t, "acme"); e.Result != audit.ResultDenied || e.DeviceID != "dev_acme_temp_over" {
			t.Fatalf("refusal not audited against the device: %+v", e)
		}
	})

	t.Run("resolving it by hostname is refused too", func(t *testing.T) {
		text, isErr := call(t, cs, proto.OpStat, map[string]any{"device": "TEMP-OVER", "path": cbsLog})
		if !isErr || !strings.HasPrefix(text, proto.ErrDeviceRevoked+": ") {
			t.Fatalf("expired temporary device answered %q", text)
		}
	})

	t.Run("an expired session is not listed", func(t *testing.T) {
		text, isErr := call(t, cs, ToolListDevices, nil)
		if isErr {
			t.Fatal(text)
		}
		var got DeviceList
		if err := json.Unmarshal([]byte(text), &got); err != nil {
			t.Fatal(err)
		}
		listed := map[string]bool{}
		for _, d := range got.Devices {
			listed[d.ID] = true
		}
		if listed["dev_acme_temp_over"] {
			t.Fatalf("an expired temporary device is offered to the AI: %s", text)
		}
		if !listed["dev_acme_temp_live"] {
			t.Fatalf("a live temporary device is missing: %s", text)
		}
	})

	t.Run("a live session is still online", func(t *testing.T) {
		d := temporaryDevice("dev_x", "X", recent, now.Add(time.Minute))
		if !d.Online(now) || d.Expired(now) {
			t.Fatal("a temporary device inside its window is not usable")
		}
		if d.Online(now.Add(2 * time.Minute)) {
			t.Fatal("a temporary device is still online past its deadline")
		}
	})
}
