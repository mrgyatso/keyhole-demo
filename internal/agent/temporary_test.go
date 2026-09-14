package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func offerServer(t *testing.T, status int, body any) (*httptest.Server, *[]proto.TempOfferRequest) {
	t.Helper()
	var got []proto.TempOfferRequest
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != proto.TempOfferPath || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req proto.TempOfferRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		got = append(got, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(s.Close)
	return s, &got
}

func TestFetchOfferReadsTheMSPsTerms(t *testing.T) {
	want := proto.TempOffer{
		Client: "acme", ClientName: "ACME Corp", Technician: "alice@msp", Reason: "ticket 4471",
		Operations: proto.ReadOps, MaxDuration: 30 * time.Minute, Ephemeral: true,
	}
	s, got := offerServer(t, http.StatusOK, want)

	o, err := agent.FetchOffer(context.Background(), s.URL, "khe_acme_secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.Client != want.Client || o.Technician != want.Technician || o.MaxDuration != want.MaxDuration {
		t.Fatalf("offer %+v", o)
	}
	if len(*got) != 1 || (*got)[0].Token != "khe_acme_secret" || (*got)[0].OS == "" {
		t.Fatalf("request %+v", *got)
	}
}

func TestFetchOfferRefusesAnythingButATemporaryOffer(t *testing.T) {
	for name, body := range map[string]proto.TempOffer{
		"managed":     {Client: "acme", MaxDuration: time.Hour},
		"no client":   {MaxDuration: time.Hour, Ephemeral: true},
		"no duration": {Client: "acme", Ephemeral: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := offerServer(t, http.StatusOK, body)
			if _, err := agent.FetchOffer(context.Background(), s.URL, "khe_acme_secret", nil); err == nil {
				t.Fatal("accepted an offer that is not a temporary install")
			}
		})
	}

	t.Run("a refusal keeps its protocol code", func(t *testing.T) {
		s, _ := offerServer(t, http.StatusUnauthorized,
			proto.HTTPError{Error: proto.Error{Code: proto.ErrInvalidToken, Message: "nope"}})
		_, err := agent.FetchOffer(context.Background(), s.URL, "khe_acme_secret", nil)
		var perr *proto.Error
		if !errors.As(err, &perr) || perr.Code != proto.ErrInvalidToken {
			t.Fatalf("error %v", err)
		}
	})

	t.Run("plain http to a public host is refused before the token is sent", func(t *testing.T) {
		if _, err := agent.FetchOffer(context.Background(), "http://relay.example.com", "khe_acme_secret", nil); err == nil {
			t.Fatal("sent a token over plain http")
		}
	})
}

func TestSelfRevokeNeedsItsOwnEnrollment(t *testing.T) {
	ctx := context.Background()
	if err := agent.SelfRevoke(ctx, nil, "creds", proto.RevokeExpired); !errors.Is(err, agent.ErrNotEnrolled) {
		t.Fatalf("revoked without an enrollment: %v", err)
	}
	e := &agent.Enrollment{DeviceID: "dev_1", NATSURLs: []string{"wss://keyhole.test/nats"}}
	if err := agent.SelfRevoke(ctx, e, "", proto.RevokeExpired); err == nil {
		t.Fatal("revoked without a credential")
	}
}

func TestTempSessionRoundTripAndMarker(t *testing.T) {
	d := agent.DataDir(filepath.Join(t.TempDir(), "session"))
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadTempSession(); !errors.Is(err, agent.ErrNoTempSession) {
		t.Fatalf("empty dir: %v", err)
	}
	if d.Terminating() {
		t.Fatal("a fresh session is already terminating")
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := &agent.TempSession{
		ID: "tmp1", State: agent.TempRunning, Client: "acme", DeviceID: "dev_1",
		EnrolledAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := d.SaveTempSession(s); err != nil {
		t.Fatal(err)
	}
	back, err := d.LoadTempSession()
	if err != nil {
		t.Fatal(err)
	}
	if back.State != agent.TempRunning || back.DeviceID != "dev_1" || !back.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatalf("session %+v", back)
	}
	if back.AgentVersion == "" {
		t.Fatal("the session does not record which agent wrote it")
	}

	// The marker is idempotent: cleanup runs more than once when a session
	// was interrupted.
	for range 2 {
		if err := d.MarkTerminating(); err != nil {
			t.Fatal(err)
		}
	}
	if !d.Terminating() {
		t.Fatal("the terminating marker did not stick")
	}

	t.Run("a truncated session file is not a session", func(t *testing.T) {
		if err := os.WriteFile(d.File(agent.TempSessionFile), []byte(`{"id":"tmp1"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := d.LoadTempSession(); !errors.Is(err, agent.ErrNoTempSession) {
			t.Fatalf("accepted an incomplete session: %v", err)
		}
	})
}

func TestWriteReceiptIsSelfDescribingAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "receipts")
	s := agent.TempSession{
		ID: "tmp1", Client: "acme", ClientName: "ACME Corp", Technician: "alice@msp",
		Reason: "ticket 4471", DeviceID: "dev_1", RelayURL: "https://keyhole.test",
	}
	ended := time.Date(2026, 9, 11, 11, 30, 0, 0, time.UTC)
	path, err := agent.WriteReceipt(dir, s.NewReceipt(ended, agent.EndExpired, 2, []string{"aa"}, true))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "keyhole-dev_1-20260911T113000Z.json" {
		t.Fatalf("receipt name %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("receipt mode %v is readable by others", info.Mode())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r agent.Receipt
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Note == "" || !strings.Contains(r.Note, "no credential") {
		t.Fatalf("receipt note %q", r.Note)
	}
	if r.Technician != "alice@msp" || r.Reason != "ticket 4471" || !r.Revoked || r.Requests != 2 {
		t.Fatalf("receipt %+v", r)
	}

	t.Run("a second session in the same second does not overwrite the first", func(t *testing.T) {
		other := s
		other.DeviceID = "dev_2"
		second, err := agent.WriteReceipt(dir, other.NewReceipt(ended, agent.EndTerminated, 0, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if second == path {
			t.Fatal("two sessions share one receipt file")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 2 {
			t.Fatalf("%d receipts (%v)", len(entries), err)
		}
	})
}

func TestTempRootIsNotTheManagedDataDir(t *testing.T) {
	managed := string(agent.DefaultDataDir())
	root := agent.TempRoot()
	if root == managed || !strings.HasPrefix(root, managed) {
		t.Fatalf("temp root %q against managed data dir %q", root, managed)
	}
	if agent.ReceiptDir() == root || strings.HasPrefix(agent.ReceiptDir(), root) {
		t.Fatalf("receipts live inside the sessions they must outlive: %q", agent.ReceiptDir())
	}
}
