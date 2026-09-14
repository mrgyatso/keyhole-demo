package companion_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

type stateReply struct {
	Technician string    `json:"technician"`
	ServerTime time.Time `json:"server_time"`
	Unlocks    []struct {
		ID          string     `json:"id"`
		ClientName  string     `json:"client_name"`
		Purpose     string     `json:"purpose"`
		State       string     `json:"state"`
		Duration    int64      `json:"duration_seconds"`
		IdleTimeout int64      `json:"idle_timeout_seconds"`
		ExpiresAt   *time.Time `json:"expires_at"`
		IdleAt      *time.Time `json:"idle_at"`
		Calls       int64      `json:"calls"`
		Devices     []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"devices"`
		Passkey string   `json:"passkey"`
		Changes []string `json:"changes"`
	} `json:"unlocks"`
	Changes []struct {
		ID         string `json:"id"`
		Op         string `json:"op"`
		ClientName string `json:"client_name"`
		Hostname   string `json:"hostname"`
		State      string `json:"state"`
		Unlock     string `json:"unlock"`
		Plan       *struct {
			Path          string `json:"path"`
			Reason        string `json:"reason"`
			BeforeSHA256  string `json:"before_sha256"`
			BeforeSize    int64  `json:"before_size"`
			AfterSHA256   string `json:"after_sha256"`
			AfterSize     int64  `json:"after_size"`
			Diff          string `json:"diff"`
			DiffTruncated bool   `json:"diff_truncated"`
			Binary        bool   `json:"binary"`
		} `json:"plan"`
	} `json:"changes"`
	Activity []struct {
		Op       string `json:"op"`
		Hostname string `json:"hostname"`
		Path     string `json:"path"`
		Result   string `json:"result"`
	} `json:"activity"`
}

func TestState(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	b := h.newTech(bob).enroll()
	pending := h.unlock(alice, "globex")
	active := h.unlock(alice, "acme")
	h.must(a.approve("unlocks", active.ID), http.StatusOK)
	c := h.change(alice, h.access(alice, active.ID))
	h.advance(time.Minute)
	used := h.clock()
	if err := h.st.RecordUnlockUse(bg, active.ID, model.UnlockActivity{Unlock: active.ID, Time: used, Op: "read_file",
		Device: h.device.ID, Path: `C:\Windows\Logs\CBS\CBS.log`, Result: "ok", Bytes: 2048}); err != nil {
		t.Fatal(err)
	}
	bobs := h.unlock(bob, "acme")
	_ = b

	r := h.get("/api/state", a.cookie)
	h.must(r, http.StatusOK)
	var s stateReply
	decodeJSON(t, r.body, &s)
	if s.Technician != alice || !s.ServerTime.Equal(h.clock()) {
		t.Fatalf("technician %q, server time %s", s.Technician, s.ServerTime)
	}
	if len(s.Unlocks) != 2 || strings.Contains(string(r.body), bobs.ID) {
		t.Fatalf("unlocks %s", r.body)
	}
	for _, u := range s.Unlocks {
		switch u.ID {
		case pending.ID:
			if u.ClientName != "Globex" || u.State != model.UnlockAwaiting || u.Duration != 3600 || u.IdleTimeout != 900 ||
				u.ExpiresAt != nil || u.Purpose != pending.Purpose {
				t.Errorf("pending unlock %+v", u)
			}
		case active.ID:
			if u.ClientName != "Acme Corp" || u.State != model.UnlockActive || u.ExpiresAt == nil || u.Calls != 1 ||
				u.IdleAt == nil || !u.IdleAt.Equal(used.Add(model.DefaultUnlockIdle)) || u.Passkey != "idp|alice's laptop" ||
				len(u.Devices) != 1 || u.Devices[0].Hostname != "SRV-ACME-01" || len(u.Changes) != 1 || u.Changes[0] != c.ID {
				t.Errorf("active unlock %+v", u)
			}
		default:
			t.Errorf("unexpected unlock %s", u.ID)
		}
	}
	if len(s.Changes) != 1 {
		t.Fatalf("changes %s", r.body)
	}
	ch := s.Changes[0]
	if ch.ID != c.ID || ch.ClientName != "Acme Corp" || ch.Hostname != "SRV-ACME-01" || ch.State != model.ChangeAwaiting ||
		ch.Unlock != active.ID || ch.Plan == nil {
		t.Fatalf("change %+v", ch)
	}
	if p := ch.Plan; p.Path != planPath || p.BeforeSHA256 != beforeHash || p.AfterSHA256 != afterHash || p.BeforeSize != 120 ||
		p.AfterSize != 124 || p.Diff != diffText || p.Binary || p.DiffTruncated || p.Reason == "" {
		t.Fatalf("plan %+v", p)
	}
	// The diff is text for the page to show as text; the JSON never carries
	// it as markup either.
	if bytes.Contains(r.body, []byte("<script>")) {
		t.Fatal("the state carries raw markup")
	}
	if len(s.Activity) != 1 || s.Activity[0].Op != "read_file" || s.Activity[0].Hostname != "SRV-ACME-01" ||
		s.Activity[0].Path != `C:\Windows\Logs\CBS\CBS.log` {
		t.Fatalf("activity %+v", s.Activity)
	}
}

func TestTheAPINeverReturnsSecrets(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice)
	link := h.mintLink(alice)
	o := h.enrollBegin(link)
	reg := a.registration(link, challengeOf(t, o.Challenge))
	enrolled := h.post("/api/enroll/finish", "", reg)
	h.must(enrolled, http.StatusOK)
	a.cookie = enrolled.cookie().Value

	u := h.unlock(alice, "acme")
	uApprove := a.approve("unlocks", u.ID)
	h.must(uApprove, http.StatusOK)

	c := h.change(alice, h.access(alice, u.ID))
	h.gate.setResult(`{"path":"x","approval":{"nonce":"leaked-nonce"},"assertion":"leaked-assertion","after_sha256":"` + afterHash + `"}`)
	cApprove := a.approve("changes", c.ID)
	h.must(cApprove, http.StatusOK)

	h.unlock(alice, "globex") // an awaiting card in the state
	state := h.get("/api/state", a.cookie)
	receipt := h.get("/api/unlocks/"+u.ID+"/receipt", a.cookie)
	lock := h.post("/api/unlocks/"+u.ID+"/lock", a.cookie, nil)
	h.must(state, http.StatusOK)
	h.must(receipt, http.StatusOK)

	storedU, _ := h.st.Unlock(bg, u.ID)
	cs, _ := h.st.CompanionSessionByToken(bg, a.cookie)
	std := base64.StdEncoding.EncodeToString
	secrets := map[string]string{
		"an approved unlock's nonce":       storedU.Nonce,
		"a change's nonce":                 c.Nonce,
		"the sign-in secret":               a.cookie,
		"the sign-in's hash":               cs.Hash,
		"the link secret":                  link,
		"the link's hash":                  model.HashSecret(link),
		"the public key":                   std(a.key.PublicKey()),
		"a nonce in the endpoint's result": "leaked-nonce",
		"an assertion in the result":       "leaked-assertion",
	}
	for what, secret := range secrets {
		if secret == "" {
			t.Fatalf("%s is empty; the check would be vacuous", what)
		}
	}
	for name, r := range map[string]reply{"enroll": enrolled, "unlock approve": uApprove, "change approve": cApprove,
		"state": state, "receipt": receipt, "lock": lock} {
		for what, secret := range secrets {
			if bytes.Contains(r.body, []byte(secret)) {
				t.Errorf("the %s reply contains %s", name, what)
			}
		}
		for _, key := range []string{`"nonce"`, `"assertion"`, `"signature"`, `"hash"`, `"public_key"`, `"grant_id"`} {
			if bytes.Contains(r.body, []byte(key)) {
				t.Errorf("the %s reply has a %s member", name, key)
			}
		}
	}

	logs := h.logs.String()
	for _, want := range []string{"passkey enrolled", "unlock approved", "change approved"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected %q in the log; the next check would be vacuous", want)
		}
	}
	for what, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains %s", what)
		}
	}
}

func TestReceipt(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	b := h.newTech(bob).enroll()
	u := h.unlock(alice, "acme")
	h.must(a.approve("unlocks", u.ID), http.StatusOK)
	acc := h.access(alice, u.ID)
	for _, act := range []model.UnlockActivity{
		{Op: "read_file", Path: `C:\Windows\Logs\CBS\CBS.log`, Result: "ok", Bytes: 2048},
		{Op: "read_file", Path: `C:\Windows\System32\config\SAM`, Result: "denied", ErrorCode: "hard_denied"},
	} {
		act.Unlock, act.Time, act.Device = u.ID, h.clock(), h.device.ID
		if err := h.st.RecordUnlockUse(bg, u.ID, act); err != nil {
			t.Fatal(err)
		}
	}
	c := h.change(alice, acc)
	h.must(a.approve("changes", c.ID), http.StatusOK)
	elsewhere := h.change(alice, h.access(alice, "")) // not made under this unlock
	h.advance(time.Minute)
	h.must(h.post("/api/unlocks/"+u.ID+"/lock", a.cookie, nil), http.StatusOK)

	r := h.get("/api/unlocks/"+u.ID+"/receipt", a.cookie)
	h.must(r, http.StatusOK)
	if !strings.HasPrefix(r.header.Get("Content-Type"), "text/plain") {
		t.Fatalf("content type %q", r.header.Get("Content-Type"))
	}
	text := string(r.body)
	for _, want := range []string{
		"Acme Corp (acme)", alice, u.Purpose, u.ID, "locked: the technician pressed Lock",
		`with passkey "idp|alice's laptop"`, "Calls        2", "SRV-ACME-01 (" + h.device.ID + ")",
		"apply " + planPath + " on SRV-ACME-01: applied",
		"before  sha256 " + beforeHash + " (120 bytes)", "after   sha256 " + afterHash + " (124 bytes)",
		`C:\Windows\Logs\CBS\CBS.log`, `C:\Windows\System32\config\SAM`, "denied (hard_denied)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the receipt lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, elsewhere.ID) {
		t.Error("the receipt lists a change made under no unlock")
	}
	if r := h.get("/api/unlocks/"+u.ID+"/receipt", b.cookie); r.status != http.StatusNotFound {
		t.Fatalf("bob read alice's receipt: %d", r.status)
	}
}
