package fstools

import (
	"strconv"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Printers are read whole from the print spooler, never through a command
// line. Listing them needs a grant that names the op, as a service query does,
// but it changes nothing and has no path scope: a printer belongs to the
// machine, not to a directory.

func (c *call) listPrinters(proto.ListPrintersArgs) (proto.PrinterInventory, error) {
	switch {
	case c.cap == nil:
		return proto.PrinterInventory{}, failf(proto.ErrConsentRequired, "%s requires an approved access grant; this request carries none", c.op)
	case !containsString(c.cap.Operations, c.op):
		return proto.PrinterInventory{}, failf(proto.ErrNotAllowed, "the approved grant does not include %s", c.op)
	}
	inv, err := inventoryPrinters(c.ctx)
	if err != nil {
		return proto.PrinterInventory{}, err
	}
	capInventory(&inv)
	inv.CheckedAt = c.x.now().UTC()
	return inv, nil
}

// capInventory bounds each list at MaxInventoryItems and gives an empty list,
// not null, when there is nothing to list.
func capInventory(inv *proto.PrinterInventory) {
	inv.Printers = capList(inv.Printers, &inv.Truncated)
	inv.Drivers = capList(inv.Drivers, &inv.Truncated)
	inv.Ports = capList(inv.Ports, &inv.Truncated)
}

func capList[T any](s []T, truncated *bool) []T {
	if s == nil {
		return []T{}
	}
	if len(s) > proto.MaxInventoryItems {
		*truncated = true
		return s[:proto.MaxInventoryItems]
	}
	return s
}

type flagName struct {
	bit  uint32
	name string
}

// printerStatusNames are the spooler's PRINTER_STATUS_* flags.
var printerStatusNames = []flagName{
	{0x00000001, "paused"}, {0x00000002, "error"}, {0x00000004, "pending_deletion"},
	{0x00000008, "paper_jam"}, {0x00000010, "paper_out"}, {0x00000020, "manual_feed"},
	{0x00000040, "paper_problem"}, {0x00000080, "offline"}, {0x00000100, "io_active"},
	{0x00000200, "busy"}, {0x00000400, "printing"}, {0x00000800, "output_bin_full"},
	{0x00001000, "not_available"}, {0x00002000, "waiting"}, {0x00004000, "processing"},
	{0x00008000, "initializing"}, {0x00010000, "warming_up"}, {0x00020000, "toner_low"},
	{0x00040000, "no_toner"}, {0x00080000, "page_punt"}, {0x00100000, "user_intervention"},
	{0x00200000, "out_of_memory"}, {0x00400000, "door_open"}, {0x00800000, "server_unknown"},
	{0x01000000, "power_save"}, {0x02000000, "server_offline"}, {0x04000000, "driver_update_needed"},
}

// printerAttributeNames are the PRINTER_ATTRIBUTE_* flags worth reporting.
var printerAttributeNames = []flagName{
	{0x00000008, "shared"}, {0x00000010, "network"}, {0x00000020, "hidden"}, {0x00000040, "local"},
	{0x00000400, "work_offline"}, {0x00000800, "bidi"}, {0x00002000, "published"},
}

// flagNames names the bits of v that names knows, in the order names lists
// them; other bits are left out.
func flagNames(v uint32, names []flagName) []string {
	var out []string
	for _, n := range names {
		if v&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// driverVersionString renders a driver's packed 64-bit version as a.b.c.d,
// or "" when it has none.
func driverVersionString(v uint64) string {
	if v == 0 {
		return ""
	}
	part := func(shift uint) string { return strconv.FormatUint(v>>shift&0xffff, 10) }
	return part(48) + "." + part(32) + "." + part(16) + "." + part(0)
}
