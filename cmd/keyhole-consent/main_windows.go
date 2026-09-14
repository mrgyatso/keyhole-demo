//go:build windows

// Command keyhole-consent is the Keyhole consent window: the per-user
// application that shows what a technician is asking to read on this
// machine, carries the answer back to the Keyhole service, and shows every
// operation performed under a live grant.
//
// It holds no authority. The service establishes who this process is from
// the pipe connection itself, and Windows decides whether the user may
// elevate. Keyhole never renders a password field: approving relaunches this
// program with the shell's "runas" verb, which is the native UAC prompt on
// the secure desktop.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent/consentipc"
	"github.com/mrgyatso/keyhole/internal/version"
)

func main() {
	fs := flag.NewFlagSet("keyhole-consent", flag.ContinueOnError)
	approve := fs.String("approve", "", "approve this access request and exit (used by the elevated relaunch)")
	approvePlan := fs.String("approve-plan", "", "approve this staged file change and exit")
	planDigest := fs.String("plan-digest", "", "digest of the staged file change")
	deny := fs.String("deny", "", "deny this access request and exit")
	sel := fs.String("select", "", "comma-separated indexes of the requested paths to grant")
	reason := fs.String("reason", "", "reason recorded with a denial")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	switch {
	case *showVersion:
		fmt.Println(version.Version)
	case *approvePlan != "":
		if *planDigest == "" {
			fmt.Fprintln(os.Stderr, "keyhole-consent: --approve-plan requires --plan-digest")
			os.Exit(2)
		}
		if err := answerPlan(*approvePlan, *planDigest); err != nil {
			fmt.Fprintln(os.Stderr, "keyhole-consent:", err)
			fatalBox(err)
			os.Exit(1)
		}
	case *approve != "" || *deny != "":
		if err := answer(*approve, *deny, *sel, *reason); err != nil {
			fmt.Fprintln(os.Stderr, "keyhole-consent:", err)
			fatalBox(err)
			os.Exit(1)
		}
	default:
		if err := runWindow(); err != nil {
			fmt.Fprintln(os.Stderr, "keyhole-consent:", err)
			fatalBox(err)
			os.Exit(1)
		}
	}
}

// answerPlan is the elevated relaunch's one-shot approval of a staged change.
// Like answer, it stays connected until the service confirms the review
// moved: the service identifies this process from the pipe, which it cannot
// do once the process has gone, so leaving early could drop the approval.
func answerPlan(accessID, digest string) error {
	c, err := consentipc.Dial(context.Background())
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.DecidePlan(accessID, digest, consentipc.DecideApprove); err != nil {
		return err
	}
	confirmed := make(chan error, 1)
	go func() {
		for {
			e, err := c.Receive()
			if err != nil {
				confirmed <- errors.New("the Keyhole service closed the connection before confirming the approval")
				return
			}
			s := e.PlanState
			if e.Type != consentipc.TypePlanState || s == nil || s.AccessID != accessID || s.Digest != digest ||
				s.State == consentipc.PlanAwaiting {
				continue
			}
			if s.State != consentipc.PlanApproved {
				confirmed <- fmt.Errorf("the change was not approved: its review is %s (%s)", s.State, s.Reason)
				return
			}
			confirmed <- nil
			return
		}
	}()
	select {
	case err := <-confirmed:
		return err
	case <-time.After(30 * time.Second):
		return errors.New("the Keyhole service did not confirm the approval")
	}
}

// answer is the one-shot mode the elevated relaunch runs in: connect, say
// what the user chose, and exit. The service checks the elevation of this
// process, not of the window the user clicked in.
func answer(approve, deny, sel, reason string) error {
	id, decision := approve, consentipc.DecideApprove
	if deny != "" {
		id, decision = deny, consentipc.DecideDeny
	}
	indexes, err := parseSelection(sel)
	if err != nil {
		return err
	}
	c, err := consentipc.Dial(context.Background())
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Decide(id, decision, indexes, reason); err != nil {
		return err
	}
	// The service answers by broadcasting the new state; waiting for it keeps
	// this process alive long enough for the write to land.
	for {
		e, err := c.Receive()
		if err != nil {
			return nil
		}
		if e.Type == consentipc.TypeState && e.State != nil && e.State.AccessID == id {
			return nil
		}
	}
}

func parseSelection(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 {
			return nil, errors.New("--select takes comma-separated path indexes")
		}
		out = append(out, n)
	}
	return out, nil
}
