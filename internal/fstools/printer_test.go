package fstools

import (
	"context"
	"runtime"
	"slices"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestPrinterFlagNames(t *testing.T) {
	if got := flagNames(0x80|0x2|0x8000_0000, printerStatusNames); !slices.Equal(got, []string{"error", "offline"}) {
		t.Errorf("status = %v", got)
	}
	if got := flagNames(0x40|0x8|0x1, printerAttributeNames); !slices.Equal(got, []string{"shared", "local"}) {
		t.Errorf("attributes = %v", got)
	}
	if got := flagNames(0, printerStatusNames); got != nil {
		t.Errorf("no flags = %v", got)
	}
}

func TestDriverVersionString(t *testing.T) {
	for v, want := range map[uint64]string{
		0:                              "",
		10<<48 | 0<<32 | 19041<<16 | 1: "10.0.19041.1",
		3<<48 | 20<<32:                 "3.20.0.0",
	} {
		if got := driverVersionString(v); got != want {
			t.Errorf("%#x = %q, want %q", v, got, want)
		}
	}
}

func TestInventoryIsCappedAndNeverNull(t *testing.T) {
	inv := proto.PrinterInventory{Printers: make([]proto.Printer, proto.MaxInventoryItems+5)}
	capInventory(&inv)
	if len(inv.Printers) != proto.MaxInventoryItems || !inv.Truncated || inv.Drivers == nil || inv.Ports == nil {
		t.Fatalf("capped to %d, truncated %t, drivers %v, ports %v", len(inv.Printers), inv.Truncated, inv.Drivers, inv.Ports)
	}
}

// Listing printers needs a grant that names the op; with one, it runs on
// Windows and says it is not implemented anywhere else.
func TestListPrintersNeedsAGrant(t *testing.T) {
	x := New(Options{})
	wantError(t, run(t, x, proto.OpListPrinters, proto.ListPrintersArgs{}, testPolicy()), proto.ErrConsentRequired)

	req := request(t, proto.OpListPrinters, proto.ListPrintersArgs{}, testPolicy())
	req.Capability = &proto.Capability{Operations: []string{proto.OpReadFile}}
	wantError(t, x.Execute(context.Background(), req), proto.ErrNotAllowed)

	req.Capability = &proto.Capability{Operations: []string{proto.OpListPrinters}}
	resp := x.Execute(context.Background(), req)
	if runtime.GOOS != "windows" {
		wantError(t, resp, proto.ErrUnsupported)
		return
	}
	if inv := result[proto.PrinterInventory](t, resp); inv.CheckedAt.IsZero() || inv.Printers == nil {
		t.Fatalf("inventory %+v", inv)
	}
}
