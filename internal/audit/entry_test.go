package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestChainVerifiesAndCatchesTampering(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	for i := range 3 {
		e := &Entry{Kind: KindTool, Client: "acme", Tool: "read_file",
			Args: json.RawMessage(`{"path":"C:\\Windows\\Logs\\CBS\\CBS.log"}`), Result: ResultOK, Bytes: int64(i)}
		if err := s.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		if e.N != uint64(i+1) {
			t.Fatalf("entry %d got n=%d", i, e.N)
		}
	}
	if err := s.Append(ctx, &Entry{Kind: KindTool, Client: "globex", Tool: "stat", Result: ResultOK}); err != nil {
		t.Fatal(err)
	}

	res, err := s.Verify(ctx, "acme")
	if err != nil || !res.OK || res.Entries != 3 {
		t.Fatalf("clean chain: %+v %v", res, err)
	}

	s.Tamper("acme", 2, func(e *Entry) { e.Bytes = 999 })
	res, _ = s.Verify(ctx, "acme")
	if res.OK || res.BadAt != 2 {
		t.Fatalf("tampered chain should fail at 2: %+v", res)
	}

	if res, _ := s.Verify(ctx, "globex"); !res.OK || res.Entries != 1 {
		t.Fatalf("other client's chain must be independent: %+v", res)
	}
}

func TestHashSurvivesJSONRoundTrip(t *testing.T) {
	at := time.Now().In(time.FixedZone("UTC+1", 3600))
	e := &Entry{Time: time.Now(), Kind: KindTool, Client: "acme", Tool: "grep",
		Args: json.RawMessage(`{ "path" : "/var/log", "pattern": "<err>" }`), AgentTime: &at, Result: ResultOK}
	if err := Seal(e, nil); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back Entry
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	h, err := back.ComputeHash()
	if err != nil || h != e.Hash {
		t.Fatalf("hash changed across a JSON round trip: %s vs %s (%v)", h, e.Hash, err)
	}
}
