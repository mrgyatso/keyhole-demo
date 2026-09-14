//go:build windows

package main

import (
	"slices"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestParseSelection(t *testing.T) {
	for in, want := range map[string][]int{"": nil, " ": nil, "0": {0}, "0,2": {0, 2}, " 1 , 3 ": {1, 3}} {
		got, err := parseSelection(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("parseSelection(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"a", "-1", "1,,2", "1;2"} {
		if _, err := parseSelection(bad); err == nil {
			t.Errorf("parseSelection(%q) was accepted", bad)
		}
	}
}

// The elevated relaunch passes --select through ShellExecute and the
// elevated copy parses it back: a narrowed selection survives the trip.
func TestSelectionSurvivesTheElevatedRelaunch(t *testing.T) {
	sel := []int{0, 3, 7}
	got, err := parseSelection(joinInts(sel))
	if err != nil || !slices.Equal(got, sel) {
		t.Fatalf("round trip of %v = %v, %v", sel, got, err)
	}
}

// Every reason the service gives for ending a request reads as words in the
// window, not as a protocol token.
func TestEveryEndReasonReadsAsWords(t *testing.T) {
	for _, r := range []string{proto.ReasonTimeout, proto.ReasonNoUser, proto.ReasonUser, proto.ReasonLogoff,
		proto.ReasonRestart, proto.ReasonUIGone, proto.ReasonExpired, proto.ReasonTechnician} {
		if got := reasonText(r); got == r || got == "" {
			t.Errorf("reason %q is shown as %q", r, got)
		}
	}
}
