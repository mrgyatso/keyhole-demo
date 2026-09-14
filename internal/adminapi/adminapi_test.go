package adminapi

import "testing"

func TestFill(t *testing.T) {
	for route, want := range map[string]string{
		RouteRevokeDevice: "/v1/admin/devices/dev_x/revoke",
		RouteAuditVerify:  "/v1/admin/clients/dev_x/audit/verify",
		RouteListClients:  "/v1/admin/clients",
	} {
		_, p := Split(route)
		if got := Fill(p, "dev_x"); got != want {
			t.Errorf("Fill(%q) = %q, want %q", p, got, want)
		}
	}
}
