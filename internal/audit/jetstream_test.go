package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// fakeConns hands out one relay connection per client account.
type fakeConns map[string]*nats.Conn

func (f fakeConns) Conn(client string) (*nats.Conn, error) {
	nc, ok := f[client]
	if !ok {
		return nil, fmt.Errorf("client %q: %w", client, model.ErrNotFound)
	}
	return nc, nil
}

// startNATS runs an embedded nats-server with one config-mode account per
// client, each with JetStream enabled, and connects a relay user to each.
func startNATS(t *testing.T, clients ...string) fakeConns {
	t.Helper()
	var accts strings.Builder
	for _, c := range clients {
		fmt.Fprintf(&accts, "  %s: {jetstream: enabled, users: [{user: %q, password: %q}]}\n", strings.ToUpper(c), c, "pw-"+c)
	}
	cfg := fmt.Sprintf("listen: 127.0.0.1:-1\nmax_payload: 8MB\n"+
		"jetstream: {store_dir: %q, max_mem_store: 64MB, max_file_store: 1GB}\n"+
		"accounts: {\n%s}\n", t.TempDir(), accts.String())
	opts := &server.Options{}
	if err := opts.ProcessConfigString(cfg); err != nil {
		t.Fatalf("nats config: %v", err)
	}
	opts.NoLog, opts.NoSigs = true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("nats-server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })

	conns := fakeConns{}
	for _, c := range clients {
		nc, err := nats.Connect(s.ClientURL(), nats.UserInfo(c, "pw-"+c))
		if err != nil {
			t.Fatalf("connect %s: %v", c, err)
		}
		t.Cleanup(nc.Close)
		conns[c] = nc
	}
	return conns
}

func toolEntry(client string, i int) *Entry {
	return &Entry{Kind: KindTool, Client: client, Tool: proto.OpReadFile, Result: ResultOK,
		Args: json.RawMessage(fmt.Sprintf(`{"device":"srv01","path":"/var/log/syslog.%d"}`, i)), Bytes: int64(100 + i)}
}

func appendN(t *testing.T, s Store, client string, n int) []Entry {
	t.Helper()
	var out []Entry
	for i := range n {
		e := toolEntry(client, i)
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("append %s #%d: %v", client, i, err)
		}
		out = append(out, *e)
	}
	return out
}

func collect(t *testing.T, s Store, client string, from, to time.Time) []Entry {
	t.Helper()
	var out []Entry
	if err := s.Range(context.Background(), client, from, to, func(e Entry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatalf("range %s: %v", client, err)
	}
	return out
}

func mustVerify(t *testing.T, s Store, client string, entries uint64) VerifyResult {
	t.Helper()
	res, err := s.Verify(context.Background(), client)
	if err != nil {
		t.Fatalf("verify %s: %v", client, err)
	}
	if !res.OK || res.Entries != entries {
		t.Fatalf("verify %s: want ok with %d entries, got %+v", client, entries, res)
	}
	return res
}

func auditStream(t *testing.T, nc *nats.Conn) jetstream.Stream {
	t.Helper()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := js.Stream(context.Background(), proto.AuditStream)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestJetStreamAppendAndVerify(t *testing.T) {
	conns := startNATS(t, "acme")
	s := NewJetStreamStore(conns)

	if res := mustVerify(t, s, "acme", 0); res.Head != "" {
		t.Fatalf("empty chain has a head: %+v", res)
	}
	got := appendN(t, s, "acme", 5)
	for i, e := range got {
		if e.N != uint64(i+1) || e.Hash == "" || e.Time.IsZero() {
			t.Fatalf("entry %d not sealed: %+v", i, e)
		}
	}
	if got[0].PrevHash != GenesisHash("acme") || got[3].PrevHash != got[2].Hash {
		t.Fatal("entries are not chained")
	}
	if res := mustVerify(t, s, "acme", 5); res.Head != got[4].Hash {
		t.Fatalf("head %s, want %s", res.Head, got[4].Hash)
	}

	// What Range returns is exactly what was sealed.
	back := collect(t, s, "acme", time.Time{}, time.Time{})
	if len(back) != 5 || back[2].Hash != got[2].Hash || string(back[2].Args) != string(got[2].Args) {
		t.Fatalf("range returned %d entries, want the 5 appended", len(back))
	}

	info, err := auditStream(t, conns["acme"]).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg := info.Config
	if !cfg.DenyDelete || !cfg.DenyPurge || cfg.Storage != jetstream.FileStorage ||
		cfg.MaxAge != 0 || cfg.Duplicates != DuplicateWindow || cfg.Discard != jetstream.DiscardNew ||
		len(cfg.Subjects) != 1 || cfg.Subjects[0] != proto.AuditSubject {
		t.Fatalf("stream config: %+v", cfg)
	}
}

func TestJetStreamChainsAreIndependentPerClient(t *testing.T) {
	conns := startNATS(t, "acme", "globex")
	s := NewJetStreamStore(conns)

	appendN(t, s, "acme", 3)
	g := appendN(t, s, "globex", 2)
	appendN(t, s, "acme", 1)

	if g[0].N != 1 || g[0].PrevHash != GenesisHash("globex") {
		t.Fatalf("globex chain did not start at genesis: %+v", g[0])
	}
	mustVerify(t, s, "acme", 4)
	mustVerify(t, s, "globex", 2)

	// Each chain lives in its own account's stream.
	for client, want := range map[string]uint64{"acme": 4, "globex": 2} {
		info, err := auditStream(t, conns[client]).Info(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.State.Msgs != want {
			t.Fatalf("%s stream holds %d messages, want %d", client, info.State.Msgs, want)
		}
	}
	for _, e := range collect(t, s, "globex", time.Time{}, time.Time{}) {
		if e.Client != "globex" {
			t.Fatalf("globex stream holds an entry for %q", e.Client)
		}
	}
}

func TestJetStreamNewStoreContinuesChain(t *testing.T) {
	conns := startNATS(t, "acme")
	first := appendN(t, NewJetStreamStore(conns), "acme", 3)

	restarted := NewJetStreamStore(conns)
	next := appendN(t, restarted, "acme", 2)
	if next[0].N != 4 || next[0].PrevHash != first[2].Hash {
		t.Fatalf("restarted store did not continue the chain: %+v", next[0])
	}
	mustVerify(t, restarted, "acme", 5)
}

func TestJetStreamStaleWriterRetriesOnNewHead(t *testing.T) {
	conns := startNATS(t, "acme")
	a, b := NewJetStreamStore(conns), NewJetStreamStore(conns)
	appendN(t, a, "acme", 1)
	appendN(t, b, "acme", 1) // b loads the head written by a
	appendN(t, a, "acme", 1) // a's cached head is now stale: its publish conflicts once
	appendN(t, b, "acme", 1)
	mustVerify(t, a, "acme", 4)
}

func TestJetStreamConcurrentWritersKeepOneChain(t *testing.T) {
	conns := startNATS(t, "acme")
	stores := []*JetStreamStore{NewJetStreamStore(conns), NewJetStreamStore(conns)}

	const perWriter = 20
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok uint64
	)
	for w, s := range stores {
		for g := range 2 {
			wg.Go(func() {
				for i := range perWriter {
					err := s.Append(context.Background(), toolEntry("acme", w*1000+g*100+i))
					mu.Lock()
					if err == nil {
						ok++
					} else {
						t.Errorf("append: %v", err)
					}
					mu.Unlock()
				}
			})
		}
	}
	wg.Wait()
	if ok != 4*perWriter {
		t.Fatalf("only %d of %d appends succeeded", ok, 4*perWriter)
	}
	mustVerify(t, stores[0], "acme", ok)
}

func TestJetStreamRefusesDeleteAndPurge(t *testing.T) {
	conns := startNATS(t, "acme")
	s := NewJetStreamStore(conns)
	appendN(t, s, "acme", 3)

	ctx := context.Background()
	st := auditStream(t, conns["acme"])
	if err := st.DeleteMsg(ctx, 2); err == nil {
		t.Fatal("deleting an audit entry succeeded")
	}
	if err := st.SecureDeleteMsg(ctx, 2); err == nil {
		t.Fatal("secure-deleting an audit entry succeeded")
	}
	if err := st.Purge(ctx); err == nil {
		t.Fatal("purging the audit stream succeeded")
	}
	js, _ := jetstream.New(conns["acme"])
	cfg := StreamConfig()
	cfg.DenyDelete, cfg.DenyPurge = false, false
	if _, err := js.UpdateStream(ctx, cfg); err == nil {
		t.Fatal("lifting delete/purge protection succeeded")
	}
	mustVerify(t, s, "acme", 3)
}

func TestJetStreamTightensUnprotectedStream(t *testing.T) {
	conns := startNATS(t, "acme")
	js, _ := jetstream.New(conns["acme"])
	loose := StreamConfig()
	loose.DenyDelete, loose.DenyPurge = false, false
	if _, err := js.CreateStream(context.Background(), loose); err != nil {
		t.Fatal(err)
	}

	appendN(t, NewJetStreamStore(conns), "acme", 1)
	info, err := auditStream(t, conns["acme"]).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Config.DenyDelete || !info.Config.DenyPurge {
		t.Fatalf("store used an unprotected stream: %+v", info.Config)
	}
}

func TestJetStreamTightensRetentionBeforeAppending(t *testing.T) {
	conns := startNATS(t, "acme")
	js, _ := jetstream.New(conns["acme"])
	unsafe := StreamConfig()
	unsafe.MaxMsgs = 1
	unsafe.Discard = jetstream.DiscardOld
	if _, err := js.CreateStream(context.Background(), unsafe); err != nil {
		t.Fatal(err)
	}

	s := NewJetStreamStore(conns)
	appendN(t, s, "acme", 2)
	mustVerify(t, s, "acme", 2)
	info, err := auditStream(t, conns["acme"]).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.MaxMsgs != -1 || info.Config.Discard != jetstream.DiscardNew {
		t.Fatalf("store left an eviction policy in place: %+v", info.Config)
	}
}

func TestJetStreamRangeTimeBounds(t *testing.T) {
	conns := startNATS(t, "acme")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	var at time.Time
	s := NewJetStreamStore(conns, WithClock(func() time.Time { return at }))
	for i := range 4 {
		at = base.Add(time.Duration(i) * 10 * time.Minute) // base, +10m, +20m, +30m
		appendN(t, s, "acme", 1)
	}

	ns := func(es []Entry) (out []uint64) {
		for _, e := range es {
			out = append(out, e.N)
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		from, to time.Time
		want     []uint64
	}{
		{"open", time.Time{}, time.Time{}, []uint64{1, 2, 3, 4}},
		{"closed", base.Add(10 * time.Minute), base.Add(30 * time.Minute), []uint64{2, 3}},
		{"from only", base.Add(25 * time.Minute), time.Time{}, []uint64{4}},
		{"to only", time.Time{}, base.Add(5 * time.Minute), []uint64{1}},
		{"from is inclusive, to exclusive", base, base.Add(10 * time.Minute), []uint64{1}},
		{"after the end", time.Now().Add(time.Hour), time.Time{}, nil},
		{"before the start", base.Add(-time.Hour), base.Add(-time.Minute), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ns(collect(t, s, "acme", tc.from, tc.to))
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got entries %v, want %v", got, tc.want)
			}
		})
	}
}

func TestJetStreamRangeUsesEntryTimesWithoutOrderingAssumptions(t *testing.T) {
	conns := startNATS(t, "acme")
	s := NewJetStreamStore(conns)
	now := time.Now().UTC().Truncate(time.Second)
	first := toolEntry("acme", 1)
	first.Time = now.Add(24 * time.Hour)
	second := toolEntry("acme", 2)
	second.Time = now
	for _, e := range []*Entry{first, second} {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}

	current := collect(t, s, "acme", now.Add(-time.Minute), now.Add(time.Minute))
	if len(current) != 1 || current[0].N != second.N {
		t.Fatalf("current range returned chain positions %v, want [%d]", entryNumbers(current), second.N)
	}
	future := collect(t, s, "acme", now.Add(23*time.Hour), now.Add(25*time.Hour))
	if len(future) != 1 || future[0].N != first.N {
		t.Fatalf("future range returned chain positions %v, want [%d]", entryNumbers(future), first.N)
	}
}

func entryNumbers(entries []Entry) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.N
	}
	return out
}

func TestJetStreamUnknownClient(t *testing.T) {
	s := NewJetStreamStore(startNATS(t, "acme"))
	err := s.Append(context.Background(), toolEntry("globex", 0))
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("append for a client without a connection: %v", err)
	}
}
