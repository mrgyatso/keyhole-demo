//go:build !windows

package fstools

import (
	"context"
	"runtime"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Printers are listed through the Windows print spooler only. Everywhere else
// the op exists in the protocol and refuses; CUPS can come later.

func inventoryPrinters(context.Context) (proto.PrinterInventory, error) {
	return proto.PrinterInventory{}, failf(proto.ErrUnsupported, "listing printers is not implemented on %s", runtime.GOOS)
}
