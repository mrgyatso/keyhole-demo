package fstools

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// The print spooler's own API, winspool.drv, lists printers, drivers and
// ports, and the Standard TCP/IP port monitor keeps each port's address in the
// registry. Nothing is started and no command line is built.

var (
	winspool               = windows.NewLazySystemDLL("winspool.drv")
	procEnumPrinters       = winspool.NewProc("EnumPrintersW")
	procEnumPrinterDrivers = winspool.NewProc("EnumPrinterDriversW")
	procEnumPorts          = winspool.NewProc("EnumPortsW")
)

const (
	printerEnumLocal       = 0x00000002
	printerEnumConnections = 0x00000004
	tcpipMonitor           = "Standard TCP/IP Port"
	tcpipPortsKey          = `SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port\Ports`
)

// printerInfo2 is PRINTER_INFO_2W.
type printerInfo2 struct {
	ServerName         *uint16
	PrinterName        *uint16
	ShareName          *uint16
	PortName           *uint16
	DriverName         *uint16
	Comment            *uint16
	Location           *uint16
	DevMode            uintptr
	SepFile            *uint16
	PrintProcessor     *uint16
	Datatype           *uint16
	Parameters         *uint16
	SecurityDescriptor uintptr
	Attributes         uint32
	Priority           uint32
	DefaultPriority    uint32
	StartTime          uint32
	UntilTime          uint32
	Status             uint32
	Jobs               uint32
	AveragePPM         uint32
}

// driverInfo8 is DRIVER_INFO_8W.
type driverInfo8 struct {
	Version                  uint32
	Name                     *uint16
	Environment              *uint16
	DriverPath               *uint16
	DataFile                 *uint16
	ConfigFile               *uint16
	HelpFile                 *uint16
	DependentFiles           *uint16
	MonitorName              *uint16
	DefaultDataType          *uint16
	PreviousNames            *uint16
	DriverDate               windows.Filetime
	DriverVersion            uint64
	MfgName                  *uint16
	OEMURL                   *uint16
	HardwareID               *uint16
	Provider                 *uint16
	PrintProcessor           *uint16
	VendorSetup              *uint16
	ColorProfiles            *uint16
	InfPath                  *uint16
	PrinterDriverAttributes  uint32
	CoreDriverDependencies   *uint16
	MinInboxDriverVerDate    windows.Filetime
	MinInboxDriverVerVersion uint64
}

// portInfo2 is PORT_INFO_2W.
type portInfo2 struct {
	PortName    *uint16
	MonitorName *uint16
	Description *uint16
	PortType    uint32
	Reserved    uint32
}

func inventoryPrinters(ctx context.Context) (proto.PrinterInventory, error) {
	if err := winspool.Load(); err != nil {
		return proto.PrinterInventory{}, failf(proto.ErrUnsupported, "the print spooler API is not available: %v", err)
	}
	inv := proto.PrinterInventory{Spooler: proto.ServiceUnknown}
	if s, err := queryService(ctx, "Spooler"); err == nil {
		inv.Spooler = s.State
	}
	if inv.Spooler != proto.ServiceRunning {
		// Nothing can be listed without the spooler, and that it is not running
		// is the finding.
		return inv, nil
	}
	var err error
	if inv.Printers, err = enumPrinters(); err != nil {
		return proto.PrinterInventory{}, err
	}
	if inv.Drivers, err = enumPrinterDrivers(); err != nil {
		return proto.PrinterInventory{}, err
	}
	if inv.Ports, err = enumPorts(); err != nil {
		return proto.PrinterInventory{}, err
	}
	return inv, nil
}

func enumPrinters() ([]proto.Printer, error) {
	buf, n, err := enumSpooler("printers", func(buf *byte, size uint32, needed, returned *uint32) error {
		return spoolerCall(procEnumPrinters, printerEnumLocal|printerEnumConnections, 0, 2,
			uintptr(unsafe.Pointer(buf)), uintptr(size), uintptr(unsafe.Pointer(needed)), uintptr(unsafe.Pointer(returned)))
	})
	if err != nil {
		return nil, err
	}
	recs := records[printerInfo2](buf, n)
	out := make([]proto.Printer, 0, len(recs))
	for _, r := range recs {
		out = append(out, proto.Printer{
			Name: str(r.PrinterName), ShareName: str(r.ShareName), Server: str(r.ServerName),
			Port: str(r.PortName), Driver: str(r.DriverName), Location: str(r.Location), Comment: str(r.Comment),
			PrintProcessor: str(r.PrintProcessor), Datatype: str(r.Datatype),
			Status: flagNames(r.Status, printerStatusNames), Attributes: flagNames(r.Attributes, printerAttributeNames),
			Jobs: int(r.Jobs),
		})
	}
	runtime.KeepAlive(buf)
	return out, nil
}

func enumPrinterDrivers() ([]proto.PrinterDriver, error) {
	buf, n, err := enumSpooler("printer drivers", func(buf *byte, size uint32, needed, returned *uint32) error {
		return spoolerCall(procEnumPrinterDrivers, 0, 0, 8,
			uintptr(unsafe.Pointer(buf)), uintptr(size), uintptr(unsafe.Pointer(needed)), uintptr(unsafe.Pointer(returned)))
	})
	if err != nil {
		return nil, err
	}
	recs := records[driverInfo8](buf, n)
	out := make([]proto.PrinterDriver, 0, len(recs))
	for _, r := range recs {
		d := proto.PrinterDriver{Name: str(r.Name), Environment: str(r.Environment), Version: int(r.Version),
			Manufacturer: str(r.MfgName), Provider: str(r.Provider), HardwareID: str(r.HardwareID),
			DriverVersion: driverVersionString(r.DriverVersion), InfPath: str(r.InfPath)}
		if r.DriverDate != (windows.Filetime{}) {
			d.DriverDate = time.Unix(0, r.DriverDate.Nanoseconds()).UTC()
		}
		out = append(out, d)
	}
	runtime.KeepAlive(buf)
	return out, nil
}

func enumPorts() ([]proto.PrinterPort, error) {
	buf, n, err := enumSpooler("printer ports", func(buf *byte, size uint32, needed, returned *uint32) error {
		return spoolerCall(procEnumPorts, 0, 2,
			uintptr(unsafe.Pointer(buf)), uintptr(size), uintptr(unsafe.Pointer(needed)), uintptr(unsafe.Pointer(returned)))
	})
	if err != nil {
		return nil, err
	}
	recs := records[portInfo2](buf, n)
	out := make([]proto.PrinterPort, 0, len(recs))
	for _, r := range recs {
		p := proto.PrinterPort{Name: str(r.PortName), Monitor: str(r.MonitorName), Description: str(r.Description)}
		if p.Monitor == tcpipMonitor {
			tcpipPort(&p)
		}
		out = append(out, p)
	}
	runtime.KeepAlive(buf)
	return out, nil
}

// tcpipPort fills in a Standard TCP/IP port's address from the port monitor's
// registry key. A port it cannot read is listed without them.
func tcpipPort(p *proto.PrinterPort) {
	if p.Name == "" || strings.ContainsAny(p.Name, `\`) {
		return
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipPortsKey+`\`+p.Name, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if p.Host, _, _ = k.GetStringValue("HostName"); p.Host == "" {
		p.Host, _, _ = k.GetStringValue("IPAddress")
	}
	if v, _, err := k.GetIntegerValue("PortNumber"); err == nil {
		p.PortNumber = int(v)
	}
	if v, _, err := k.GetIntegerValue("Protocol"); err == nil {
		switch v {
		case 1:
			p.Protocol = "raw"
		case 2:
			p.Protocol = "lpr"
		}
	}
	p.Queue, _, _ = k.GetStringValue("Queue")
	if v, _, err := k.GetIntegerValue("SNMP Enabled"); err == nil {
		p.SNMP = v != 0
	}
}

// enumSpooler runs one of the spooler's Enum* calls, which fill the caller's
// buffer with fixed-size records followed by the strings they point into: ask
// for the size, then fill a buffer that big, again if the list grew between.
func enumSpooler(what string, call func(buf *byte, size uint32, needed, returned *uint32) error) ([]byte, uint32, error) {
	var needed, returned uint32
	err := call(nil, 0, &needed, &returned)
	for tries := 0; errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) && needed > 0 && tries < 3; tries++ {
		buf := make([]byte, needed)
		if err = call(&buf[0], needed, &needed, &returned); err == nil {
			return buf, returned, nil
		}
	}
	if err != nil {
		return nil, 0, failf(proto.ErrIO, "listing %s: %v", what, err)
	}
	return nil, 0, nil // nothing to list
}

// spoolerCall calls one winspool function, which returns zero on failure.
func spoolerCall(p *windows.LazyProc, args ...uintptr) error {
	if r, _, err := p.Call(args...); r == 0 {
		return err
	}
	return nil
}

// records views the first n fixed-size records of buf.
func records[T any](buf []byte, n uint32) []T {
	var zero T
	if n == 0 || uintptr(len(buf)) < uintptr(n)*unsafe.Sizeof(zero) {
		return nil
	}
	return unsafe.Slice((*T)(unsafe.Pointer(&buf[0])), n)
}

func str(p *uint16) string { return windows.UTF16PtrToString(p) }
