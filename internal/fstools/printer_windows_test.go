package fstools

import (
	"context"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Every Windows machine with a running spooler has ports (LPT1:, FILE:,
// PORTPROMPT:) and usually Microsoft's own printers and drivers, so the
// inventory of a real machine can be checked for shape.
func TestListPrintersOnWindows(t *testing.T) {
	req := request(t, proto.OpListPrinters, proto.ListPrintersArgs{}, testPolicy())
	req.Capability = &proto.Capability{Operations: []string{proto.OpListPrinters}}
	inv := result[proto.PrinterInventory](t, New(Options{}).Execute(context.Background(), req))
	t.Logf("spooler %s: %d printers, %d drivers, %d ports", inv.Spooler, len(inv.Printers), len(inv.Drivers), len(inv.Ports))
	if inv.Spooler != proto.ServiceRunning {
		t.Skipf("the print spooler is %s", inv.Spooler)
	}
	if len(inv.Ports) == 0 {
		t.Error("a running spooler reported no ports")
	}
	for _, p := range inv.Printers {
		if p.Name == "" || p.Driver == "" || p.Port == "" {
			t.Errorf("printer %+v lacks a name, driver or port", p)
		}
	}
	for _, d := range inv.Drivers {
		if d.Name == "" || d.Environment == "" || d.Version == 0 {
			t.Errorf("driver %+v lacks a name, environment or version", d)
		}
	}
	for _, p := range inv.Ports {
		if p.Name == "" {
			t.Errorf("a port has no name: %+v", p)
		}
		if p.Monitor == tcpipMonitor && p.Host == "" {
			t.Errorf("TCP/IP port %s has no address", p.Name)
		}
	}
}
