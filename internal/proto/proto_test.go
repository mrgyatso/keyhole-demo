package proto

import "testing"

func TestDeviceFromSubject(t *testing.T) {
	if id, ok := DeviceFromSubject(EventSubject("dev_abc", EvtHeartbeat)); !ok || id != "dev_abc" {
		t.Fatalf("got %q %v", id, ok)
	}
	if id, ok := DeviceFromSubject(RPCSubject("dev_abc", OpReadFile)); !ok || id != "dev_abc" {
		t.Fatalf("got %q %v", id, ok)
	}
	for _, bad := range []string{AuditSubject, "kh.d.", "kh.d.dev", "x.d.dev.rpc.ping"} {
		if _, ok := DeviceFromSubject(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}
