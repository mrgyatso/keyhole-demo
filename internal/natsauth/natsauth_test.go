package natsauth_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/natsauth/natsauthtest"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func newOperator(t *testing.T) *natsauth.Operator {
	t.Helper()
	op, err := natsauth.NewOperator("keyhole-test")
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestServerConf(t *testing.T) {
	op := newOperator(t)
	dir := t.TempDir()
	cfg := natsauth.ServerConfig{Dir: dir}
	if err := natsauth.WriteServerDir(op, cfg); err != nil {
		t.Fatal(err)
	}
	opts, err := server.ProcessConfigFile(filepath.Join(dir, natsauth.ConfFile))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		ok   bool
	}{
		{"client listener on 127.0.0.1:4222", opts.Host == "127.0.0.1" && opts.Port == 4222},
		{"monitor on 127.0.0.1:8222", opts.HTTPHost == "127.0.0.1" && opts.HTTPPort == 8222},
		{"websocket on 127.0.0.1:7810", opts.Websocket.Host == "127.0.0.1" && opts.Websocket.Port == 7810},
		{"websocket without TLS, compressed", opts.Websocket.NoTLS && opts.Websocket.Compression},
		{"max_payload 8 MiB", opts.MaxPayload == natsauth.MaxPayload},
		{"system account", opts.SystemAccount == op.SysAccount},
		{"trusted operator", len(opts.TrustedOperators) == 1 && opts.TrustedOperators[0].Subject == op.PublicKey},
		{"strict signing keys", len(opts.TrustedOperators) == 1 && opts.TrustedOperators[0].StrictSigningKeyUsage},
		{"jetstream under the nats dir", opts.JetStream && opts.StoreDir == filepath.Join(dir, natsauth.JetStreamDir)},
		{"jetstream file quota", opts.JetStreamMaxStore == natsauth.DefaultMaxFileStore},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("%s: not so in the generated config", c.name)
		}
	}
	if _, ok := opts.AccountResolver.(*server.DirAccResolver); !ok {
		t.Errorf("resolver is %T, want the full dir resolver", opts.AccountResolver)
	}
	if err := natsauth.WriteServerDir(op, cfg); err == nil {
		t.Error("WriteServerDir replaced an existing config")
	}
	if _, err := op.ServerConf(natsauth.ServerConfig{Dir: "relative/nats"}); err == nil {
		t.Error("relative nats dir accepted")
	}
}

func TestOperatorFileRoundTrip(t *testing.T) {
	op := newOperator(t)
	path := filepath.Join(t.TempDir(), "operator.json")
	if err := op.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	got, err := natsauth.LoadOperator(path)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *op {
		t.Fatal("loaded operator differs from the saved one")
	}
	if err := op.WriteFile(path); err == nil {
		t.Fatal("WriteFile replaced an existing file")
	}

	other := newOperator(t)
	mixed := *op
	mixed.SysAccountJWT = other.SysAccountJWT
	mixedPath := filepath.Join(t.TempDir(), "mixed.json")
	if err := mixed.WriteFile(mixedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := natsauth.LoadOperator(mixedPath); err == nil {
		t.Fatal("LoadOperator accepted a SYS account JWT from another operator")
	}
}

func TestCredsRoundTrip(t *testing.T) {
	op := newOperator(t)
	c, err := op.NewSysUser("sys")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := natsauth.ParseCreds(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatal("parsed creds differ")
	}
	other, err := op.NewSysUser("other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := natsauth.ParseCreds([]byte(strings.Replace(string(b), c.Seed, other.Seed, 1))); err == nil {
		t.Fatal("ParseCreds accepted a seed that does not match the jwt")
	}
}

func TestDeviceJWTRejectsBadInput(t *testing.T) {
	op := newOperator(t)
	a, err := op.NewAccount("acme")
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := nkeys.CreateUser()
	pub, _ := kp.PublicKey()
	for _, id := range []string{"", "dev.x", "dev_*", "dev_>", "dev x"} {
		if _, err := natsauth.DeviceJWT(a.PublicKey, a.SigningSeed, id, pub); err == nil {
			t.Errorf("device id %q accepted", id)
		}
	}
	if _, err := natsauth.DeviceJWT(a.PublicKey, a.SigningSeed, "dev_x", a.PublicKey); err == nil {
		t.Error("account key accepted as a device key")
	}
}

// conn is a test connection that records async errors (permission
// violations arrive that way) and closure.
type conn struct {
	*nats.Conn
	errs   chan error
	closed chan struct{}
}

func dial(t *testing.T, url string, c natsauth.UserCreds) *conn {
	t.Helper()
	cl, err := tryDial(url, c)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(cl.Close)
	return cl
}

func tryDial(url string, c natsauth.UserCreds) (*conn, error) {
	cl := &conn{errs: make(chan error, 64), closed: make(chan struct{})}
	nc, err := nats.Connect(url, c.Option(), nats.NoReconnect(),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case cl.errs <- err:
			default:
			}
		}),
		nats.ClosedHandler(func(*nats.Conn) { close(cl.closed) }))
	if err != nil {
		return nil, err
	}
	cl.Conn = nc
	return cl, nil
}

// expectDenied waits for the server's permissions violation for subject.
func (c *conn) expectDenied(t *testing.T, subject string) {
	t.Helper()
	_ = c.Flush()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case err := <-c.errs:
			if errors.Is(err, nats.ErrPermissionViolation) && strings.Contains(err.Error(), `"`+subject+`"`) {
				return
			}
		case <-deadline:
			t.Fatalf("no permissions violation for %q", subject)
		}
	}
}

func expectNothing(t *testing.T, sub *nats.Subscription) {
	t.Helper()
	if msg, err := sub.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("unexpected message on %s", msg.Subject)
	}
}

func newAccount(t *testing.T, op *natsauth.Operator, sys *nats.Conn, name string) *natsauth.Account {
	t.Helper()
	a, err := op.NewAccount(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := natsauth.Push(context.Background(), sys, a.JWT); err != nil {
		t.Fatal(err)
	}
	return a
}

func deviceCreds(t *testing.T, a *natsauth.Account, id string) natsauth.UserCreds {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	tok, err := natsauth.DeviceJWT(a.PublicKey, a.SigningSeed, id, pub)
	if err != nil {
		t.Fatal(err)
	}
	return natsauth.UserCreds{JWT: tok, Seed: string(seed)}
}

func respondWith(t *testing.T, c *conn, deviceID, answer string) {
	t.Helper()
	_, err := c.Subscribe(proto.RPCWildcard(deviceID), func(m *nats.Msg) {
		_ = m.Respond([]byte(answer))
		if strings.HasSuffix(m.Subject, ".twice") {
			_ = m.Respond([]byte(answer))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestTenantIsolation is security invariant #3 (and the NATS half of #2):
// a device credential reaches only its own subjects, an account sees nothing
// of another, and a revoked device is cut off.
func TestTenantIsolation(t *testing.T) {
	op := newOperator(t)
	s := natsauthtest.StartServer(t, op)
	url := s.ClientURL()

	sysCreds, err := op.NewSysUser("relay-sys")
	if err != nil {
		t.Fatal(err)
	}
	sys := dial(t, url, sysCreds)
	acme := newAccount(t, op, sys.Conn, "acme")
	globex := newAccount(t, op, sys.Conn, "globex")

	relayA := dial(t, url, acme.Relay)
	relayB := dial(t, url, globex.Relay)
	devA := dial(t, url, deviceCreds(t, acme, "dev_a"))
	devB := dial(t, url, deviceCreds(t, globex, "dev_b"))
	// A globex device that reuses acme's device ID: the account, not the ID,
	// is the boundary.
	devB2 := dial(t, url, deviceCreds(t, globex, "dev_a"))

	respondWith(t, devA, "dev_a", "acme")
	respondWith(t, devB, "dev_b", "globex")
	respondWith(t, devB2, "dev_a", "globex")

	t.Run("relay request reaches only its own account's device", func(t *testing.T) {
		for _, c := range []struct {
			relay *conn
			want  string
		}{{relayA, "acme"}, {relayB, "globex"}} {
			msg, err := c.relay.Request(proto.RPCSubject("dev_a", proto.OpPing), nil, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if string(msg.Data) != c.want {
				t.Fatalf("got answer %q, want %q", msg.Data, c.want)
			}
		}
		if _, err := relayA.Request(proto.RPCSubject("dev_b", proto.OpPing), nil, 300*time.Millisecond); err == nil {
			t.Fatal("acme's relay reached a globex device")
		}
	})

	t.Run("device serves over websocket", func(t *testing.T) {
		ws := dial(t, s.WebsocketURL(), deviceCreds(t, acme, "dev_ws"))
		respondWith(t, ws, "dev_ws", "ws")
		msg, err := relayA.Request(proto.RPCSubject("dev_ws", proto.OpPing), nil, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if string(msg.Data) != "ws" {
			t.Fatalf("got %q", msg.Data)
		}
	})

	t.Run("events reach only the device's own account", func(t *testing.T) {
		subA, err := relayA.SubscribeSync(proto.AllEventsWildcard)
		if err != nil {
			t.Fatal(err)
		}
		subB, err := relayB.SubscribeSync(proto.AllEventsWildcard)
		if err != nil {
			t.Fatal(err)
		}
		_ = relayA.Flush()
		_ = relayB.Flush()
		if err := devA.Publish(proto.EventSubject("dev_a", proto.EvtHeartbeat), []byte("a")); err != nil {
			t.Fatal(err)
		}
		_ = devA.Flush()
		if msg, err := subA.NextMsg(2 * time.Second); err != nil || string(msg.Data) != "a" {
			t.Fatalf("acme relay did not get its device's event: %v", err)
		}
		expectNothing(t, subB)
		if err := devB.Publish(proto.EventSubject("dev_b", proto.EvtHeartbeat), []byte("b")); err != nil {
			t.Fatal(err)
		}
		_ = devB.Flush()
		if msg, err := subB.NextMsg(2 * time.Second); err != nil || string(msg.Data) != "b" {
			t.Fatalf("globex relay did not get its device's event: %v", err)
		}
		expectNothing(t, subA)
	})

	t.Run("device is confined to its own subjects", func(t *testing.T) {
		for _, subj := range []string{
			proto.RPCSubject("dev_a", proto.OpPing),      // publishing rpc
			proto.EventSubject("dev_b", proto.EvtHello),  // another device's events
			proto.AuditSubject,                           // the audit stream
			"$JS.API.INFO",                               // JetStream
			"$JS.API.STREAM.CREATE." + proto.AuditStream, // JetStream
			"$SYS.REQ.SERVER.PING",                       // system account
			"_INBOX.anything",                            // someone's inbox
			"kh.d.dev_a.evt",                             // not under its evt tree
			"kh.other",                                   // anything else
		} {
			if err := devA.Publish(subj, nil); err != nil {
				t.Fatal(err)
			}
			devA.expectDenied(t, subj)
		}
		for _, subj := range []string{
			proto.RPCWildcard("dev_b"),
			proto.AllRPCWildcard,
			proto.AllEventsWildcard,
			proto.EventWildcard("dev_a"),
			"_INBOX.>",
			"$SYS.>",
			"$JS.>",
			">",
		} {
			if _, err := devA.SubscribeSync(subj); err != nil {
				t.Fatal(err)
			}
			devA.expectDenied(t, subj)
		}
	})

	t.Run("device answers each request once", func(t *testing.T) {
		inbox := relayA.NewInbox()
		sub, err := relayA.SubscribeSync(inbox)
		if err != nil {
			t.Fatal(err)
		}
		if err := relayA.PublishRequest(proto.RPCSubject("dev_a", "twice"), inbox, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := sub.NextMsg(2 * time.Second); err != nil {
			t.Fatal(err)
		}
		devA.expectDenied(t, inbox)
		expectNothing(t, sub)
	})

	t.Run("device cannot use JetStream", func(t *testing.T) {
		js, err := jetstream.New(devA.Conn)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := js.AccountInfo(ctx); err == nil {
			t.Fatal("device reached the JetStream API")
		}
	})

	t.Run("relay cannot reach the system account", func(t *testing.T) {
		if err := relayA.Publish("$SYS.REQ.SERVER.PING", nil); err != nil {
			t.Fatal(err)
		}
		relayA.expectDenied(t, "$SYS.REQ.SERVER.PING")
		if err := relayA.Publish(natsauth.ClaimsUpdateSubject, []byte(acme.JWT)); err != nil {
			t.Fatal(err)
		}
		relayA.expectDenied(t, natsauth.ClaimsUpdateSubject)
	})

	t.Run("relay keeps an undeletable audit stream per account", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		js, err := jetstream.New(relayA.Conn)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := js.CreateStream(ctx, jetstream.StreamConfig{
			Name:       proto.AuditStream,
			Subjects:   []string{proto.AuditSubject},
			Storage:    jetstream.FileStorage,
			DenyDelete: true,
			DenyPurge:  true,
		})
		if err != nil {
			t.Fatal(err)
		}
		ack, err := js.Publish(ctx, proto.AuditSubject, []byte(`{"n":1}`), jetstream.WithExpectLastSequence(0))
		if err != nil {
			t.Fatal(err)
		}
		if ack.Sequence != 1 {
			t.Fatalf("sequence %d", ack.Sequence)
		}
		if err := stream.DeleteMsg(ctx, 1); err == nil {
			t.Fatal("deleted an audit message")
		}
		if err := stream.Purge(ctx); err == nil {
			t.Fatal("purged the audit stream")
		}
		msg, err := stream.GetMsg(ctx, 1)
		if err != nil || string(msg.Data) != `{"n":1}` {
			t.Fatalf("read back: %v", err)
		}
		cons, err := js.OrderedConsumer(ctx, proto.AuditStream, jetstream.OrderedConsumerConfig{})
		if err != nil {
			t.Fatal(err)
		}
		m, err := cons.Next(jetstream.FetchMaxWait(2 * time.Second))
		if err != nil || string(m.Data()) != `{"n":1}` {
			t.Fatalf("ordered consumer: %v", err)
		}

		jsB, err := jetstream.New(relayB.Conn)
		if err != nil {
			t.Fatal(err)
		}
		streamB, err := jsB.CreateStream(ctx, jetstream.StreamConfig{
			Name: proto.AuditStream, Subjects: []string{proto.AuditSubject},
			Storage: jetstream.FileStorage, DenyDelete: true, DenyPurge: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := streamB.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.State.Msgs != 0 {
			t.Fatalf("globex's audit stream holds %d of acme's messages", info.State.Msgs)
		}
	})

	t.Run("revoked device is disconnected and cannot reconnect", func(t *testing.T) {
		creds := deviceCreds(t, acme, "dev_gone")
		gone := dial(t, url, creds)
		kp, err := nkeys.FromSeed([]byte(creds.Seed))
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := kp.PublicKey()

		updated, changed, err := op.Revoke(acme.JWT, map[string]time.Time{pub: time.Now()})
		if err != nil || !changed {
			t.Fatalf("revoke: changed=%v err=%v", changed, err)
		}
		if again, changed, err := op.Revoke(updated, map[string]time.Time{pub: time.Now().Add(-time.Hour)}); err != nil || changed || again != updated {
			t.Fatalf("re-revoking changed the jwt: changed=%v err=%v", changed, err)
		}
		if err := natsauth.Push(context.Background(), sys.Conn, updated); err != nil {
			t.Fatal(err)
		}
		select {
		case <-gone.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("revoked device still connected")
		}
		if c, err := tryDial(url, creds); err == nil {
			c.Close()
			t.Fatal("revoked device reconnected")
		}
		if !devA.IsConnected() {
			t.Fatal("revoking one device disconnected another")
		}
	})

	t.Run("push reports the server's refusal", func(t *testing.T) {
		if err := natsauth.Push(context.Background(), sys.Conn, "not-a-jwt"); err == nil {
			t.Fatal("push of garbage succeeded")
		}
		if _, _, err := newOperator(t).Revoke(acme.JWT, nil); err == nil {
			t.Fatal("another operator re-signed acme's account")
		}
	})
}
