package hostinfo

import (
	"context"
	"runtime"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	ubuntu := []byte(`PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
`)
	if got := parseOSRelease(ubuntu); got != "Ubuntu 24.04.1 LTS" {
		t.Errorf("ubuntu: %q", got)
	}
	minimal := []byte("# comment\nNAME=Alpine\nVERSION_ID=3.20.2\n")
	if got := parseOSRelease(minimal); got != "Alpine 3.20.2" {
		t.Errorf("minimal: %q", got)
	}
	if got := parseOSRelease(nil); got != "" {
		t.Errorf("empty: %q", got)
	}
}

func TestParseIOPlatformUUID(t *testing.T) {
	out := []byte(`+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000253, registered, matched, active, busy 0 (1234 ms), retain 42>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "4C4C4544-0042-3510-8044-B4C04F4D4E31"
      "model" = <"MacBookPro18,1">
    }
`)
	got, err := parseIOPlatformUUID(out)
	if err != nil || got != "4C4C4544-0042-3510-8044-B4C04F4D4E31" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := parseIOPlatformUUID([]byte("nothing here")); err == nil {
		t.Error("want error for missing UUID")
	}
}

func TestWindowsVersion(t *testing.T) {
	cases := []struct {
		product, display, build string
		ubr                     uint64
		want                    string
	}{
		{"Windows Server 2025 Datacenter Evaluation", "24H2", "26100", 1742, "Windows Server 2025 Datacenter Evaluation 24H2 (build 26100.1742)"},
		{"Windows 10 Pro", "23H2", "22631", 4169, "Windows 11 Pro 23H2 (build 22631.4169)"},
		{"Windows 10 Enterprise", "22H2", "19045", 0, "Windows 10 Enterprise 22H2 (build 19045)"},
		{"Windows Server 2016 Standard", "", "14393", 7428, "Windows Server 2016 Standard (build 14393.7428)"},
	}
	for _, c := range cases {
		if got := windowsVersion(c.product, c.display, c.build, c.ubr); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestGatherOnThisMachine(t *testing.T) {
	info, err := Gather(context.Background())
	if err != nil {
		t.Logf("partial: %v", err) // CI containers may lack a machine id
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH || info.Hostname == "" {
		t.Errorf("info = %+v", info)
	}
}
