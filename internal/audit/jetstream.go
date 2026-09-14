package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// DuplicateWindow is how long JetStream remembers the Nats-Msg-Id (the entry
// hash) of each append, so a retried publish of the same entry is stored once.
const DuplicateWindow = 2 * time.Minute

// StreamConfig is the configuration of a client's audit stream, which lives in
// that client's own NATS account. Nothing may delete, purge or roll it up,
// and when the account's storage quota is full new appends fail rather than
// old entries being dropped. There is no age limit: retention is a Phase 2
// policy. The relay may create the stream with this config when it creates a
// client; JetStreamStore creates it on first use otherwise.
func StreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              proto.AuditStream,
		Description:       "Keyhole hash-chained audit log",
		Subjects:          []string{proto.AuditSubject},
		Retention:         jetstream.LimitsPolicy,
		Discard:           jetstream.DiscardNew,
		Storage:           jetstream.FileStorage,
		Replicas:          1,
		MaxMsgs:           -1,
		MaxBytes:          -1,
		MaxMsgsPerSubject: -1,
		MaxMsgSize:        -1,
		Duplicates:        DuplicateWindow,
		DenyDelete:        true,
		DenyPurge:         true,
	}
}

// JetStreamStore is the durable Store: one JetStream stream per client, inside
// that client's NATS account, reached through the relay's connection for the
// client. Appends use expected-last-sequence, so two writers cannot fork a
// chain: a loser reloads the head and retries until the append deadline.
type JetStreamStore struct {
	conns   model.Conns
	now     func() time.Time
	log     *slog.Logger
	timeout time.Duration

	mu     sync.Mutex
	chains map[string]*chain
}

// chain is the store's view of one client's stream.
type chain struct {
	mu      sync.Mutex // serialises appends and guards the fields below
	nc      *nats.Conn // connection the handles below were made on
	js      jetstream.JetStream
	stream  jetstream.Stream
	loaded  bool   // head and lastSeq reflect the stream
	head    *Entry // last entry, nil for an empty chain
	lastSeq uint64 // stream sequence of head
}

// Option configures a JetStreamStore.
type Option func(*JetStreamStore)

// WithClock sets the clock used to stamp entries whose Time is zero.
func WithClock(now func() time.Time) Option { return func(s *JetStreamStore) { s.now = now } }

// WithLogger sets the logger. The default discards.
func WithLogger(l *slog.Logger) Option { return func(s *JetStreamStore) { s.log = l } }

// WithTimeout bounds each Append, including stream creation and head
// recovery. The default is 10 seconds.
func WithTimeout(d time.Duration) Option { return func(s *JetStreamStore) { s.timeout = d } }

// NewJetStreamStore returns a Store that keeps each client's chain in the
// KH_AUDIT stream of that client's account.
func NewJetStreamStore(conns model.Conns, opts ...Option) *JetStreamStore {
	s := &JetStreamStore{
		conns:   conns,
		now:     time.Now,
		log:     slog.New(slog.DiscardHandler),
		timeout: 10 * time.Second,
		chains:  map[string]*chain{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Append seals e onto client's chain and returns once JetStream has stored it.
func (s *JetStreamStore) Append(ctx context.Context, e *Entry) error {
	if e.Client == "" {
		return errors.New("audit: entry has no client")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	c := s.chainFor(e.Client)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := s.openLocked(ctx, e.Client, c); err != nil {
		return err
	}
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	for {
		if !c.loaded {
			if err := c.load(ctx); err != nil {
				return fmt.Errorf("audit: %s: %w", e.Client, err)
			}
		}
		err := c.publish(ctx, e)
		if err == nil {
			return nil
		}
		// After any failure the head is uncertain (a timed-out publish may
		// still have been stored), so the next attempt reloads it.
		c.loaded = false
		if isWrongLastSeq(err) {
			s.log.Debug("audit: another writer appended; retrying on the new head", "client", e.Client)
			continue
		}
		return fmt.Errorf("audit: append to %s: %w", e.Client, err)
	}
}

// Range calls fn for client's entries with from <= Time < to, in chain order.
func (s *JetStreamStore) Range(ctx context.Context, client string, from, to time.Time, fn func(Entry) error) error {
	// Entry.Time is part of the signed record and may intentionally differ
	// from the JetStream storage timestamp. Walk the bounded stream snapshot
	// and filter on entry time so Range always honors the Store contract.
	return s.scan(ctx, client, time.Time{}, func(seq uint64, data []byte) (bool, error) {
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			return false, fmt.Errorf("audit: %s: stream message %d is not an entry: %w", client, seq, err)
		}
		if (!from.IsZero() && e.Time.Before(from)) || (!to.IsZero() && !e.Time.Before(to)) {
			return true, nil
		}
		return true, fn(e)
	})
}

// Verify walks client's whole chain from its first entry.
func (s *JetStreamStore) Verify(ctx context.Context, client string) (VerifyResult, error) {
	v := NewVerifier(client)
	var unreadable *VerifyResult
	err := s.scan(ctx, client, time.Time{}, func(seq uint64, data []byte) (bool, error) {
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			r := v.Result()
			r.OK, r.BadAt = false, r.Entries+1
			r.Reason = fmt.Sprintf("stream message %d is not an audit entry: %v", seq, err)
			unreadable = &r
			return false, nil
		}
		return v.Next(e), nil
	})
	if err != nil {
		return VerifyResult{}, err
	}
	if unreadable != nil {
		return *unreadable, nil
	}
	return v.Result(), nil
}

func (s *JetStreamStore) chainFor(client string) *chain {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.chains[client]
	if c == nil {
		c = &chain{}
		s.chains[client] = c
	}
	return c
}

// openLocked makes sure c has handles on the client's current connection and
// that the audit stream exists. The relay may replace a client's connection
// (for example after an account update), so the handles follow it. c.mu must
// be held.
func (s *JetStreamStore) openLocked(ctx context.Context, client string, c *chain) error {
	nc, err := s.conns.Conn(client)
	if err != nil {
		return fmt.Errorf("audit: connection for %s: %w", client, err)
	}
	if c.stream != nil && c.nc == nc {
		return nil
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("audit: jetstream for %s: %w", client, err)
	}
	st, err := ensureStream(ctx, js)
	if err != nil {
		return fmt.Errorf("audit: stream for %s: %w", client, err)
	}
	c.nc, c.js, c.stream = nc, js, st
	return nil
}

// streamFor returns client's audit stream handle for reading.
func (s *JetStreamStore) streamFor(ctx context.Context, client string) (jetstream.Stream, error) {
	c := s.chainFor(client)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := s.openLocked(ctx, client, c); err != nil {
		return nil, err
	}
	return c.stream, nil
}

// scan feeds fn the raw entries of client's stream in order, starting at the
// first message stored at or after start (the beginning if start is zero) and
// ending at the last message present when the scan began, or when fn returns
// false or an error.
func (s *JetStreamStore) scan(ctx context.Context, client string, start time.Time, fn func(seq uint64, data []byte) (bool, error)) error {
	st, err := s.streamFor(ctx, client)
	if err != nil {
		return err
	}
	info, err := st.Info(ctx)
	if err != nil {
		return fmt.Errorf("audit: %s: stream info: %w", client, err)
	}
	last := info.State
	if last.Msgs == 0 || (!start.IsZero() && last.LastTime.Before(start)) {
		return nil
	}
	cfg := jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverAllPolicy}
	if !start.IsZero() {
		cfg.DeliverPolicy, cfg.OptStartTime = jetstream.DeliverByStartTimePolicy, &start
	}
	cons, err := st.OrderedConsumer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("audit: %s: consumer: %w", client, err)
	}
	it, err := cons.Messages()
	if err != nil {
		return fmt.Errorf("audit: %s: consumer: %w", client, err)
	}
	defer it.Stop()
	for {
		msg, err := it.Next(jetstream.NextContext(ctx))
		if err != nil {
			return fmt.Errorf("audit: %s: read: %w", client, err)
		}
		md, err := msg.Metadata()
		if err != nil {
			return fmt.Errorf("audit: %s: message metadata: %w", client, err)
		}
		more, err := fn(md.Sequence.Stream, msg.Data())
		if err != nil || !more || md.Sequence.Stream >= last.LastSeq {
			return err
		}
	}
}

// load recovers the chain head from the stream, so a restarted relay (or a
// second writer) continues the chain where it ends.
func (c *chain) load(ctx context.Context) error {
	msg, err := c.stream.GetLastMsgForSubject(ctx, proto.AuditSubject)
	switch {
	case errors.Is(err, jetstream.ErrMsgNotFound):
		c.head, c.lastSeq = nil, 0
	case err != nil:
		return fmt.Errorf("load chain head: %w", err)
	default:
		var e Entry
		if err := json.Unmarshal(msg.Data, &e); err != nil {
			return fmt.Errorf("chain head (stream message %d) is not an entry: %w", msg.Sequence, err)
		}
		c.head, c.lastSeq = &e, msg.Sequence
	}
	c.loaded = true
	return nil
}

// publish seals e after the loaded head and stores it only if the stream still
// ends at that head.
func (c *chain) publish(ctx context.Context, e *Entry) error {
	if err := Seal(e, c.head); err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	ack, err := c.js.Publish(ctx, proto.AuditSubject, data,
		jetstream.WithExpectStream(proto.AuditStream),
		jetstream.WithExpectLastSequence(c.lastSeq),
		jetstream.WithMsgID(e.Hash))
	if err != nil {
		return err
	}
	// A duplicate ack is still a success: the Msg-Id is the entry hash, which
	// fixes the entry's content and position, so JetStream already holds it.
	stored := *e
	c.head, c.lastSeq, c.loaded = &stored, ack.Sequence, true
	return nil
}

// ensureStream opens the audit stream, creating it if needed, and refuses to
// use one that could lose entries.
func ensureStream(ctx context.Context, js jetstream.JetStream) (jetstream.Stream, error) {
	want := StreamConfig()
	st, err := js.Stream(ctx, want.Name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		st, err = js.CreateStream(ctx, want)
		if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			st, err = js.Stream(ctx, want.Name) // created concurrently
		}
	}
	if err != nil {
		return nil, err
	}
	cfg := st.CachedInfo().Config
	if safeStreamConfig(cfg) {
		return st, nil
	}
	// Tighten every setting that can remove, replace, redirect or fail to
	// persist an entry. Delete/purge flags alone are insufficient: DiscardOld,
	// MaxAge or a message limit can silently cut the start of the chain.
	hardenStreamConfig(&cfg)
	st, err = js.UpdateStream(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("existing %s stream has unsafe retention settings and could not be updated: %w", want.Name, err)
	}
	if cfg = st.CachedInfo().Config; !safeStreamConfig(cfg) {
		return nil, fmt.Errorf("existing %s stream still has unsafe retention settings after update", want.Name)
	}
	return st, nil
}

func safeStreamConfig(cfg jetstream.StreamConfig) bool {
	return slices.Equal(cfg.Subjects, []string{proto.AuditSubject}) &&
		cfg.Retention == jetstream.LimitsPolicy && cfg.Discard == jetstream.DiscardNew &&
		cfg.Storage == jetstream.FileStorage && cfg.MaxMsgs == -1 && cfg.MaxBytes == -1 &&
		cfg.MaxAge == 0 && cfg.MaxMsgsPerSubject == -1 && cfg.MaxMsgSize == -1 &&
		!cfg.NoAck && cfg.Mirror == nil && len(cfg.Sources) == 0 &&
		cfg.SubjectTransform == nil && cfg.RePublish == nil &&
		cfg.DenyDelete && cfg.DenyPurge && !cfg.AllowRollup &&
		!cfg.DiscardNewPerSubject && !cfg.AllowMsgTTL && cfg.SubjectDeleteMarkerTTL == 0
}

func hardenStreamConfig(cfg *jetstream.StreamConfig) {
	want := StreamConfig()
	cfg.Subjects = want.Subjects
	cfg.Retention = want.Retention
	cfg.MaxMsgs = want.MaxMsgs
	cfg.MaxBytes = want.MaxBytes
	cfg.Discard = want.Discard
	cfg.DiscardNewPerSubject = false
	cfg.MaxAge = 0
	cfg.MaxMsgsPerSubject = want.MaxMsgsPerSubject
	cfg.MaxMsgSize = want.MaxMsgSize
	cfg.Storage = want.Storage
	cfg.NoAck = false
	cfg.Mirror = nil
	cfg.Sources = nil
	cfg.DenyDelete = true
	cfg.DenyPurge = true
	cfg.AllowRollup = false
	cfg.SubjectTransform = nil
	cfg.RePublish = nil
	cfg.AllowMsgTTL = false
	cfg.SubjectDeleteMarkerTTL = 0
}

func isWrongLastSeq(err error) bool {
	var apiErr *jetstream.APIError
	return errors.As(err, &apiErr) &&
		(apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence ||
			apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant)
}
