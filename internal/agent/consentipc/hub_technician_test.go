package consentipc

import (
	"context"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// A grant a technician unlock approved on its own never passes through the
// consent window, yet the runner reports every operation under it to the
// endpoint's consent adapter, and on Windows that report reaches this hub
// (Slice 6). The window must show nothing for a grant it never held: on a
// managed device the person at the machine sees nothing from Keyhole.
func TestHubShowsNoActivityForAGrantItNeverHeld(t *testing.T) {
	h := NewHub(HubOptions{Sessions: func() []string { return []string{"2"} }})
	v, sent := view(h, "2", `ACME\sam`, false)
	h.AddView(v)
	h.Activity(proto.ConsentActivity{AccessID: "acc_technician", Op: proto.OpReadFile,
		Path: `C:\ProgramData\Vendor\app.log`, Time: time.Now()})
	for _, e := range sent() {
		if e.Type == TypeActivity {
			t.Fatalf("the window was shown activity for a grant it never held: %+v", e.Activity)
		}
	}

	// A grant the window is holding still shows its activity.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := h.Request(ctx, testRequest()); err != nil {
		t.Fatal(err)
	}
	h.Activity(proto.ConsentActivity{AccessID: "acc_one", Op: proto.OpReadFile, Path: `C:\Windows\Logs\x.log`, Time: time.Now()})
	shown := false
	for _, e := range sent() {
		shown = shown || (e.Type == TypeActivity && e.Activity.AccessID == "acc_one")
	}
	if !shown {
		t.Fatal("the window was not shown activity for a grant it holds")
	}
}
