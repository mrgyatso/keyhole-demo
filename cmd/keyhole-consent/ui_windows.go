//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/walk"
	"github.com/tailscale/win"
	"golang.org/x/sys/windows"

	"github.com/mrgyatso/keyhole/internal/agent/consentipc"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// ui is the consent window. Everything that touches a widget runs on the UI
// thread; the pipe reader hands work over with Synchronize.
type ui struct {
	mw       *walk.MainWindow
	header   *walk.TextLabel
	cards    *walk.Composite
	activity *walk.TextEdit
	client   *consentipc.Client

	hello   consentipc.Hello
	reqs    []consentipc.RequestView // newest last
	boxes   []*walk.CheckBox         // the ticked paths of the request on screen
	approve *walk.PushButton         // nil unless a request is waiting for an answer
	shown   string                   // access ID and state the cards were built for

	reviews   []consentipc.PlanView // change reviews waiting to be shown, oldest first
	reviewing *consentipc.PlanView  // the change review on screen, if any
	reviewDlg *walk.Dialog          // its dialog
	planDone  map[string]string     // reviews the service has said are over, by planKey
}

func runWindow() error {
	app, err := walk.InitApp()
	if err != nil {
		return err
	}
	c, err := consentipc.Dial(context.Background())
	if err != nil {
		return err
	}
	defer c.Close()
	u := &ui{client: c, planDone: map[string]string{}}
	if err := u.build(); err != nil {
		return err
	}
	go u.read()
	go u.countdown()
	app.Run()
	return nil
}

func (u *ui) build() error {
	mw, err := walk.NewMainWindowWithCfg(&walk.MainWindowCfg{Name: "KeyholeConsent",
		Bounds: walk.Rectangle{Width: 760, Height: 620}})
	if err != nil {
		return err
	}
	u.mw = mw
	mw.SetTitle("Keyhole — access request")
	mw.SetExitOnClose(false)
	// Closing the window only hides it: the service must keep seeing this
	// application, because a grant nobody is watching is paused.
	mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		*canceled = true
		mw.SetVisible(false)
	})
	if err := mw.SetLayout(walk.NewVBoxLayout()); err != nil {
		return err
	}
	if u.header, err = walk.NewTextLabel(mw); err != nil {
		return err
	}
	u.header.SetText("Waiting for the Keyhole service…")
	if u.cards, err = walk.NewComposite(mw); err != nil {
		return err
	}
	if err := u.cards.SetLayout(walk.NewVBoxLayout()); err != nil {
		return err
	}
	group, err := walk.NewGroupBox(mw)
	if err != nil {
		return err
	}
	group.SetTitle("Activity on this machine")
	if err := group.SetLayout(walk.NewVBoxLayout()); err != nil {
		return err
	}
	if u.activity, err = walk.NewTextEditWithStyle(group, win.WS_VSCROLL|win.ES_MULTILINE); err != nil {
		return err
	}
	u.activity.SetReadOnly(true)
	return nil
}

// read pumps the pipe. When the service goes away the window says so and
// stops: a window with no service has nothing to show.
func (u *ui) read() {
	for {
		e, err := u.client.Receive()
		if err != nil {
			u.mw.Synchronize(func() {
				if err == io.EOF {
					u.header.SetText("The Keyhole service has stopped. Close this window.")
					return
				}
				u.header.SetText("Lost the connection to the Keyhole service: " + err.Error())
			})
			return
		}
		env := e
		u.mw.Synchronize(func() { u.apply(env) })
	}
}

func (u *ui) apply(e consentipc.Envelope) {
	switch e.Type {
	case consentipc.TypeHello:
		if e.Hello != nil {
			u.hello = *e.Hello
			u.refresh()
		}
	case consentipc.TypeRequest:
		if e.Request == nil {
			return
		}
		u.upsert(*e.Request)
		u.refresh()
		u.show()
	case consentipc.TypeState:
		if e.State == nil {
			return
		}
		u.applyState(*e.State)
		u.refresh()
	case consentipc.TypeActivity:
		if e.Activity != nil {
			u.appendActivity(*e.Activity)
		}
	case consentipc.TypePlan:
		if e.Plan != nil {
			u.queueReview(*e.Plan)
		}
	case consentipc.TypePlanState:
		if e.PlanState != nil {
			u.planState(*e.PlanState)
		}
	}
}

func (u *ui) upsert(r consentipc.RequestView) {
	for i := range u.reqs {
		if u.reqs[i].AccessID == r.AccessID {
			u.reqs[i] = r
			return
		}
	}
	u.reqs = append(u.reqs, r)
}

func (u *ui) applyState(s consentipc.StateView) {
	for i := range u.reqs {
		if u.reqs[i].AccessID != s.AccessID {
			continue
		}
		u.reqs[i].State = s.State
		if s.Approver != "" {
			u.reqs[i].Approver = s.Approver
		}
		if len(s.Effective) > 0 {
			u.reqs[i].Effective = s.Effective
		}
		if s.State == proto.ConsentTerminated || s.State == proto.ConsentDenied {
			u.appendLine(fmt.Sprintf("%-8s %s", strings.ToUpper(s.State), reasonText(s.Reason)))
			u.reqs = slices.Delete(u.reqs, i, i+1)
			u.shown = ""
		}
		return
	}
}

// current is the request the window is showing: the one still waiting for an
// answer, or else the live grant.
func (u *ui) current() *consentipc.RequestView {
	for i := range u.reqs {
		if u.reqs[i].State == proto.ConsentAwaiting {
			return &u.reqs[i]
		}
	}
	if len(u.reqs) > 0 {
		return &u.reqs[len(u.reqs)-1]
	}
	return nil
}

// refresh rebuilds the cards for the current request. Activity does not go
// through here, so a busy session does not rebuild the window.
func (u *ui) refresh() {
	r := u.current()
	if r == nil {
		u.header.SetText(fmt.Sprintf("Keyhole is idle on %s. Nothing is being accessed.", u.machine()))
		u.clearCards()
		u.shown = ""
		return
	}
	what := "read files"
	if slices.ContainsFunc(r.Operations, proto.ChangeOp) {
		what = "read and change files"
	}
	u.header.SetText(fmt.Sprintf("%s (%s) is asking to %s on %s for client %s.",
		r.Technician, r.State, what, u.machine(), r.Client))
	if u.shown == r.AccessID+"/"+r.State {
		u.updateCountdown()
		return
	}
	u.shown = r.AccessID + "/" + r.State
	u.clearCards()
	u.buildCard(*r)
	u.cards.SetSuspended(false)
}

func (u *ui) machine() string {
	if u.hello.Hostname != "" {
		return u.hello.Hostname
	}
	host, _ := os.Hostname()
	return host
}

func (u *ui) clearCards() {
	u.boxes, u.approve = nil, nil
	children := u.cards.Children()
	for i := children.Len() - 1; i >= 0; i-- {
		children.At(i).Dispose()
	}
}

// buildCard draws one request: who is asking, why, for how long, and exactly
// which locations. Every location is a tick box, so approving a subset is
// the same gesture as approving all of it.
func (u *ui) buildCard(r consentipc.RequestView) {
	u.cards.SetSuspended(true)
	label := func(parent walk.Container, text string) {
		l, err := walk.NewTextLabel(parent)
		if err == nil {
			l.SetText(text)
		}
	}
	label(u.cards, "Purpose: "+r.Purpose)
	label(u.cards, fmt.Sprintf("Access: %s for up to %s, idle timeout %s",
		strings.Join(r.Operations, ", "), roundDur(r.Duration), roundDur(r.IdleTimeout)))
	label(u.cards, u.deadlineText(r))

	group, err := walk.NewGroupBox(u.cards)
	if err != nil {
		return
	}
	group.SetTitle("Locations this would allow")
	if err := group.SetLayout(walk.NewVBoxLayout()); err != nil {
		return
	}
	granted := r.State != proto.ConsentAwaiting
	for i, p := range r.Paths {
		cb, err := walk.NewCheckBox(group)
		if err != nil {
			continue
		}
		cb.SetText(p)
		cb.SetChecked(!granted || slices.Contains(r.Effective, p))
		cb.SetEnabled(!granted)
		cb.CheckedChanged().Attach(u.updateApproveLabel)
		u.boxes = append(u.boxes, cb)
		_ = i
	}

	row, err := walk.NewComposite(u.cards)
	if err != nil {
		return
	}
	if err := row.SetLayout(walk.NewHBoxLayout()); err != nil {
		return
	}
	button := func(text string, fn func()) *walk.PushButton {
		b, err := walk.NewPushButton(row)
		if err != nil {
			return nil
		}
		b.SetText(text)
		b.Clicked().Attach(fn)
		return b
	}
	id := r.AccessID
	if r.State == proto.ConsentAwaiting {
		u.approve = button("Approve", func() { u.decide(id, consentipc.DecideApprove) })
		button("Deny", func() { u.decide(id, consentipc.DecideDeny) })
		u.updateApproveLabel()
		label(u.cards, "Approving asks Windows for administrator confirmation. Keyhole never asks for your password itself.")
		return
	}
	if r.State == proto.ConsentPaused {
		button("Resume", func() { u.control(id, consentipc.ControlResume) })
	} else {
		button("Pause", func() { u.control(id, consentipc.ControlPause) })
	}
	button("Terminate", func() { u.control(id, consentipc.ControlEnd) })
	if r.Approver != "" {
		label(u.cards, "Approved by "+r.Approver)
	}
}

func (u *ui) deadlineText(r consentipc.RequestView) string {
	if r.State == proto.ConsentAwaiting {
		return fmt.Sprintf("Decide within %s, or Keyhole refuses this request.", roundDur(time.Until(r.DecideBy)))
	}
	return fmt.Sprintf("Access ends in %s (at %s).", roundDur(time.Until(r.ExpiresAt)), r.ExpiresAt.Local().Format("15:04:05"))
}

// selection is the indexes of the paths the user left ticked.
func (u *ui) selection() []int {
	var out []int
	for i, cb := range u.boxes {
		if cb.Checked() {
			out = append(out, i)
		}
	}
	return out
}

func (u *ui) updateApproveLabel() {
	if u.approve == nil {
		return
	}
	if n := len(u.selection()); n < len(u.boxes) {
		u.approve.SetText(fmt.Sprintf("Approve %d of %d locations", n, len(u.boxes)))
		u.approve.SetEnabled(n > 0)
		return
	}
	u.approve.SetText("Approve")
	u.approve.SetEnabled(true)
}

// decide answers a request. Approving and narrowing need an elevated
// caller, so an unelevated window relaunches itself through the shell's
// "runas" verb: Windows shows its own consent prompt on the secure desktop
// and the elevated copy sends the answer.
func (u *ui) decide(accessID, decision string) {
	sel := u.selection()
	if decision == consentipc.DecideApprove && !elevated() {
		args := []string{"--approve", accessID}
		if len(sel) > 0 && len(sel) < len(u.boxes) {
			args = append(args, "--select", joinInts(sel))
		}
		if err := relaunchElevated(args); err != nil {
			u.warn("Windows did not confirm the approval: " + err.Error())
		}
		return
	}
	var err error
	if decision == consentipc.DecideApprove {
		err = u.client.Decide(accessID, decision, sel, "")
	} else {
		err = u.client.Decide(accessID, decision, nil, "denied at the endpoint")
	}
	if err != nil {
		u.warn(err.Error())
	}
}

func (u *ui) control(accessID, action string) {
	if err := u.client.Control(accessID, action); err != nil {
		u.warn(err.Error())
	}
}

// Change reviews are shown one at a time, in the order the service sent them.
// The dialog is modal, and Walk keeps delivering the pipe's messages while it
// is open, so a second plan only joins the queue, and the service saying a
// review is over closes its dialog without an answer being sent.

func planKey(accessID, digest string) string { return accessID + "/" + digest }

// queueReview takes a plan to review. A newer plan for the same grant
// replaces one still waiting in the queue; the service ends the older review
// itself.
func (u *ui) queueReview(p consentipc.PlanView) {
	if _, over := u.planDone[planKey(p.AccessID, p.Digest)]; over {
		return
	}
	u.reviews = slices.DeleteFunc(u.reviews, func(q consentipc.PlanView) bool { return q.AccessID == p.AccessID })
	u.reviews = append(u.reviews, p)
	u.mw.Synchronize(u.nextReview)
}

// planState records that a review moved. Any state but awaiting means the
// review is over: it leaves the queue, and an open dialog for it closes.
func (u *ui) planState(s consentipc.PlanStateView) {
	if s.State == consentipc.PlanAwaiting {
		return
	}
	key := planKey(s.AccessID, s.Digest)
	u.planDone[key] = s.State
	u.reviews = slices.DeleteFunc(u.reviews, func(q consentipc.PlanView) bool { return planKey(q.AccessID, q.Digest) == key })
	if u.reviewing != nil && planKey(u.reviewing.AccessID, u.reviewing.Digest) == key && u.reviewDlg != nil {
		u.reviewDlg.Close(walk.DlgCmdAbort)
	}
	switch s.State {
	case consentipc.PlanApproved:
		u.appendLine(fmt.Sprintf("%-8s change approved by %s", "REVIEW", s.Approver))
	case consentipc.PlanDenied:
		u.appendLine(fmt.Sprintf("%-8s change refused by %s", "REVIEW", s.Approver))
	default:
		u.appendLine(fmt.Sprintf("%-8s change review closed: %s", "REVIEW", s.Reason))
	}
}

// nextReview shows the oldest queued review, if none is on screen, and acts
// on the answer once its dialog closes.
func (u *ui) nextReview() {
	if u.reviewing != nil || len(u.reviews) == 0 {
		return
	}
	p := u.reviews[0]
	u.reviews = u.reviews[1:]
	u.reviewing = &p
	u.show()
	result := u.runReview(p)
	u.reviewing, u.reviewDlg = nil, nil
	_, over := u.planDone[planKey(p.AccessID, p.Digest)]
	switch {
	case result == walk.DlgCmdAbort || over:
		// The service ended this review while it was open: nothing to answer.
	case result == walk.DlgCmdOK:
		u.approvePlan(p)
	default:
		// Deny, the close box, or a dialog that could not be built all refuse.
		u.denyPlan(p)
	}
	u.mw.Synchronize(u.nextReview)
}

// runReview shows one plan: who wants the change, why, the file, and the
// exact bounded diff, scrollable, in a fixed-width font. Deny is the default
// button, so Enter never approves by accident.
func (u *ui) runReview(p consentipc.PlanView) int {
	dlg, err := walk.NewDialog(u.mw)
	if err != nil {
		u.warn("Keyhole could not show the change for review, so it was refused: " + err.Error())
		return walk.DlgCmdCancel
	}
	defer dlg.Dispose()
	u.reviewDlg = dlg
	dlg.SetTitle("Keyhole — review a file change")
	if err := dlg.SetLayout(walk.NewVBoxLayout()); err != nil {
		return walk.DlgCmdCancel
	}
	tech, reason := p.Technician, p.Reason
	if tech == "" {
		tech = "A technician"
	}
	if reason == "" {
		reason = "(none given)"
	}
	if intro, err := walk.NewTextLabel(dlg); err == nil {
		intro.SetText(fmt.Sprintf("%s wants to change a file on %s. Nothing has been written.\n\nFile: %s\nReason: %s\n"+
			"Review by %s. Lines starting with - are removed, lines starting with + are added.",
			tech, u.machine(), p.Path, reason, p.ExpiresAt.Local().Format("15:04:05")))
	}
	diff, err := walk.NewTextEditWithStyle(dlg, win.WS_VSCROLL|win.WS_HSCROLL|win.ES_MULTILINE|win.ES_AUTOHSCROLL)
	if err != nil {
		return walk.DlgCmdCancel
	}
	diff.SetReadOnly(true)
	if font, err := walk.NewFont("Consolas", 10, 0); err == nil {
		diff.SetFont(font)
	}
	diff.SetText(strings.ReplaceAll(p.Diff, "\n", "\r\n"))
	row, err := walk.NewComposite(dlg)
	if err != nil {
		return walk.DlgCmdCancel
	}
	if err := row.SetLayout(walk.NewHBoxLayout()); err != nil {
		return walk.DlgCmdCancel
	}
	approve, err := walk.NewPushButton(row)
	if err != nil {
		return walk.DlgCmdCancel
	}
	approve.SetText("Approve change…")
	approve.Clicked().Attach(dlg.Accept)
	deny, err := walk.NewPushButton(row)
	if err != nil {
		return walk.DlgCmdCancel
	}
	deny.SetText("Deny")
	deny.Clicked().Attach(dlg.Cancel)
	_ = dlg.SetDefaultButton(deny)
	_ = dlg.SetCancelButton(deny)
	if note, err := walk.NewTextLabel(dlg); err == nil {
		note.SetText("Approving asks Windows for administrator confirmation. Deny, or closing this window, refuses the change.")
	}
	_ = dlg.SetMinMaxSize(walk.Size{Width: 640, Height: 460}, walk.Size{})
	_ = dlg.SetSize(walk.Size{Width: 860, Height: 620})
	return dlg.Run()
}

// approvePlan approves the reviewed digest. An unelevated window relaunches
// itself through UAC, and the elevated copy answers; if Windows does not
// confirm, the review is shown again so it can still be answered.
func (u *ui) approvePlan(p consentipc.PlanView) {
	if elevated() {
		if err := u.client.DecidePlan(p.AccessID, p.Digest, consentipc.DecideApprove); err != nil {
			u.warn(err.Error())
		}
		return
	}
	if err := relaunchElevated([]string{"--approve-plan", p.AccessID, "--plan-digest", p.Digest}); err != nil {
		u.warn("Windows did not confirm the change approval: " + err.Error())
		if _, over := u.planDone[planKey(p.AccessID, p.Digest)]; !over {
			u.reviews = append([]consentipc.PlanView{p}, u.reviews...)
		}
	}
}

// denyPlan refuses the reviewed digest. Refusing never needs elevation.
func (u *ui) denyPlan(p consentipc.PlanView) {
	if err := u.client.DecidePlan(p.AccessID, p.Digest, consentipc.DecideDeny); err != nil {
		u.warn(err.Error())
	}
}

func (u *ui) warn(msg string) {
	walk.MsgBox(u.mw, "Keyhole", msg, walk.MsgBoxIconWarning)
}

// show brings the window to the front when something needs an answer.
func (u *ui) show() {
	u.mw.SetVisible(true)
	win.SetForegroundWindow(u.mw.Handle())
}

// countdown keeps the deadline honest without rebuilding the window.
func (u *ui) countdown() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		u.mw.Synchronize(u.updateCountdown)
	}
}

func (u *ui) updateCountdown() {
	r := u.current()
	if r == nil || u.cards.Children().Len() < 3 {
		return
	}
	if l, ok := u.cards.Children().At(2).(*walk.TextLabel); ok {
		l.SetText(u.deadlineText(*r))
	}
}

func (u *ui) appendActivity(a proto.ConsentActivity) {
	op := strings.ToUpper(a.Op)
	line := fmt.Sprintf("%-8s %s", op, a.Path)
	switch {
	case a.ErrorCode != "":
		line = fmt.Sprintf("%-8s %s — refused (%s)", "DENIED", a.Path, a.ErrorCode)
	case a.Bytes > 0:
		line += fmt.Sprintf("  (%d bytes)", a.Bytes)
	}
	u.appendLine(line)
}

func (u *ui) appendLine(line string) {
	u.activity.AppendText(time.Now().Format("15:04:05") + "  " + line + "\r\n")
}

func reasonText(reason string) string {
	switch reason {
	case proto.ReasonTimeout:
		return "nobody answered in time"
	case proto.ReasonNoUser:
		return "nobody was signed in"
	case proto.ReasonUser:
		return "ended here"
	case proto.ReasonLogoff:
		return "the approver signed out"
	case proto.ReasonRestart:
		return "the Keyhole service restarted"
	case proto.ReasonUIGone:
		return "this window was not available"
	case proto.ReasonExpired:
		return "the access expired"
	case proto.ReasonTechnician:
		return "the technician ended it"
	case "":
		return "finished"
	}
	return reason
}

func roundDur(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	if d >= time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Second).String()
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

// elevated reports whether this process holds an elevated token.
func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated starts this same executable with the shell's "runas"
// verb, which is the native Windows UAC prompt on the secure desktop.
// Keyhole never sees the credential.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(args, " "))
	if err != nil {
		return err
	}
	cwd, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	const swShowNormal = 1
	return windows.ShellExecute(0, verb, file, params, cwd, swShowNormal)
}

// fatalBox reports a startup failure where a user can see it: this program
// is normally started with no console.
func fatalBox(err error) {
	walk.MsgBox(nil, "Keyhole consent", err.Error(), walk.MsgBoxIconError)
}
