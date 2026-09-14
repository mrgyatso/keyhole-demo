package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Inventory (Slice 9): read-only views of a machine's configuration that are
// not files. Each runs under a grant whose operations include it, like the
// service tools, and its output is the machine's own data, so it is shown
// inside the untrusted-data boundary.

// ListPrintersInput is the input of list_printers.
type ListPrintersInput struct {
	Device   string `json:"device" jsonschema:"The machine whose printers to list: its device ID (dev_...) or its hostname, as shown by list_devices."`
	AccessID string `json:"access_id" jsonschema:"Approved access request ID whose operations include list_printers."`
}

func (g *Gateway) addInventoryTools(srv *mcp.Server, c caller) {
	no := false
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, DestructiveHint: &no}
	mcp.AddTool(srv, &mcp.Tool{Name: proto.OpListPrinters, Title: "List printers", Annotations: ro,
		Description: "List a machine's printers as its print spooler reports them: each queue's port, driver, status flags and waiting jobs; the installed printer drivers with version, provider and driver package; and the ports, with each TCP/IP port's printer address. It also says whether the print spooler is running. Compare two machines of the same client to see why a printer works on one and not the other. It shows printers installed for the whole machine, not a signed-in user's own connections to a print server."},
		func(ctx context.Context, req *mcp.CallToolRequest, in ListPrintersInput) (*mcp.CallToolResult, any, error) {
			return g.runOp(ctx, c, opCall{tool: proto.OpListPrinters, device: in.Device, accessID: in.AccessID,
				input: rawArgs(req), args: proto.ListPrintersArgs{}, render: renderPrinters,
				before: requireOp(proto.OpListPrinters, nil)}), nil, nil
		})
}

// renderPrinters states the counts, then shows the inventory as the machine
// reported it, inside the untrusted-data boundary: printer names, comments and
// locations are whatever someone typed on that machine.
func renderPrinters(d model.Device, r *proto.Response) (*mcp.CallToolResult, error) {
	var inv proto.PrinterInventory
	if err := json.Unmarshal(r.Result, &inv); err != nil {
		return nil, err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, r.Result, "", "  "); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "device: %s | print spooler: %s | printers: %d | drivers: %d | ports: %d | truncated: %t | checked: %s\n",
		deviceLabel(d), inv.Spooler, len(inv.Printers), len(inv.Drivers), len(inv.Ports), inv.Truncated,
		inv.CheckedAt.UTC().Format(time.RFC3339))
	if inv.Spooler != proto.ServiceRunning {
		b.WriteString("The print spooler is not running, so nothing could be listed; that alone stops every printer on this machine.\n")
	}
	writeUntrusted(&b, d, "printers", pretty.String())
	return textResult(b.String()), nil
}
