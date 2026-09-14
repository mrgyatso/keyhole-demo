package proto

import "time"

// Inventory (Slice 9). Read-only views of a machine's configuration that are
// not files, so the agent can compare the machines of one client under one
// unlock: a printer that works on one machine and not on another, say. Like
// the change ops, each needs a capability whose Operations contain the op; it
// changes nothing, and a path scope does not apply to it.

// OpListPrinters lists the printers installed for the whole machine, with
// their drivers and ports.
const OpListPrinters = "list_printers"

// MaxInventoryItems bounds each list an inventory returns.
const MaxInventoryItems = 200

// ListPrintersArgs takes nothing: a machine's printers are listed whole.
type ListPrintersArgs struct{}

// PrinterInventory is a machine's printers as its print spooler reports them.
// The agent runs as a service, so it sees the printers installed for the
// machine, not a signed-in user's own connections to a print server.
type PrinterInventory struct {
	Spooler   string          `json:"spooler"` // the print spooler service's state, a Service* value
	Printers  []Printer       `json:"printers"`
	Drivers   []PrinterDriver `json:"drivers"`
	Ports     []PrinterPort   `json:"ports"`
	Truncated bool            `json:"truncated,omitempty"` // a list was cut at MaxInventoryItems
	CheckedAt time.Time       `json:"checked_at"`
}

// Printer is one print queue.
type Printer struct {
	Name           string   `json:"name"`
	ShareName      string   `json:"share_name,omitempty"`
	Server         string   `json:"server,omitempty"` // the print server of a connection
	Port           string   `json:"port"`
	Driver         string   `json:"driver"`
	Location       string   `json:"location,omitempty"`
	Comment        string   `json:"comment,omitempty"`
	PrintProcessor string   `json:"print_processor,omitempty"`
	Datatype       string   `json:"datatype,omitempty"`
	Status         []string `json:"status,omitempty"`     // e.g. offline, error, paper_jam; empty when the spooler reports nothing wrong
	Attributes     []string `json:"attributes,omitempty"` // e.g. local, network, shared, work_offline
	Jobs           int      `json:"jobs"`                 // documents waiting in its queue
}

// PrinterDriver is one installed printer driver.
type PrinterDriver struct {
	Name          string    `json:"name"`
	Environment   string    `json:"environment"` // e.g. Windows x64
	Version       int       `json:"version"`     // the driver model: 3 or 4 on current Windows
	Manufacturer  string    `json:"manufacturer,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	HardwareID    string    `json:"hardware_id,omitempty"`
	DriverVersion string    `json:"driver_version,omitempty"` // a.b.c.d
	DriverDate    time.Time `json:"driver_date,omitzero"`
	InfPath       string    `json:"inf_path,omitempty"` // the driver package in the driver store
}

// PrinterPort is one port a printer can print to.
type PrinterPort struct {
	Name        string `json:"name"`
	Monitor     string `json:"monitor,omitempty"` // e.g. Standard TCP/IP Port, Local Port, WSD Port
	Description string `json:"description,omitempty"`
	Host        string `json:"host,omitempty"` // a TCP/IP port's printer address
	PortNumber  int    `json:"port_number,omitempty"`
	Protocol    string `json:"protocol,omitempty"` // raw or lpr
	Queue       string `json:"queue,omitempty"`    // an LPR port's queue name
	SNMP        bool   `json:"snmp,omitempty"`
}
