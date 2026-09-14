package companion

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

func TestCeremoniesAreBoundedAndTakenOnce(t *testing.T) {
	cs := newCeremonies(3)
	t0 := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		cs.put(fmt.Sprint(i), ceremony{challenge: []byte{byte(i)}, issued: t0.Add(time.Duration(i) * time.Second)})
	}
	if n := cs.size(); n != 3 {
		t.Fatalf("%d ceremonies held, want 3", n)
	}
	at := t0.Add(10 * time.Second)
	for _, k := range []string{"0", "1"} {
		if _, ok := cs.take(k, at); ok {
			t.Errorf("ceremony %s survived a full table", k)
		}
	}
	if c, ok := cs.take("4", at); !ok || c.challenge[0] != 4 {
		t.Fatalf("take 4: %v %v", c, ok)
	}
	if _, ok := cs.take("4", at); ok {
		t.Fatal("a ceremony was taken twice")
	}
	// Replacing a ceremony evicts nothing else.
	cs.put("2", ceremony{issued: t0.Add(11 * time.Second)})
	if n := cs.size(); n != 2 {
		t.Fatalf("%d held after a replace, want 2", n)
	}
	// A lapsed ceremony is not handed out, and is swept when another arrives.
	late := t0.Add(11*time.Second + model.CeremonyTimeout + time.Second)
	if _, ok := cs.take("3", late); ok {
		t.Fatal("a lapsed ceremony was handed out")
	}
	cs.put("5", ceremony{issued: late})
	if n := cs.size(); n != 1 {
		t.Fatalf("%d held after the sweep, want 1", n)
	}
	for i := range 10000 {
		cs.put(fmt.Sprint("flood", i), ceremony{issued: late})
	}
	if n := cs.size(); n != 3 {
		t.Fatalf("a flood grew the table to %d", n)
	}
}

// nothing stands in for the store, directory and gate where a test must not
// reach them: any call panics.
type nothing struct {
	model.ApprovalStore
	model.Directory
	model.ApprovalGate
}

func TestSignInFloodStaysBounded(t *testing.T) {
	var n nothing
	s, err := New(Config{Store: n, Directory: n, Gate: n, Origin: "https://keyhole.test"})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 * maxCeremonies {
		req := httptest.NewRequest(http.MethodPost, "/api/login/begin", strings.NewReader("{}"))
		req.Header.Set("Origin", "https://keyhole.test")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("login begin: %d %s", w.Code, w.Body)
		}
	}
	if got := s.logins.size(); got != maxCeremonies {
		t.Fatalf("%d sign-in ceremonies held, want the cap %d", got, maxCeremonies)
	}
}
