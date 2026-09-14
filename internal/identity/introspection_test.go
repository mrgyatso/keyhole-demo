package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

func TestIntrospectorRequiresMFAAndAudience(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	claims := response{Active: true, Sub: "tech_alice", Name: "Alice", Exp: now.Add(time.Hour).Unix(), Aud: audience{"keyhole"}, AMR: []string{"mfa"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "client" || pass != "secret" || r.FormValue("token") == "" {
			t.Error("introspection request omitted credentials or token")
		}
		_ = json.NewEncoder(w).Encode(claims)
	}))
	defer srv.Close()
	i, err := NewIntrospector(Config{Endpoint: srv.URL, ClientID: "client", ClientSecret: "secret", Audience: "keyhole", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	got, err := i.AuthenticateTechnician(context.Background(), "opaque-token")
	if err != nil || got.Technician != "tech_alice" || !got.MFA || got.ID == "" {
		t.Fatalf("identity = %+v, %v", got, err)
	}
	claims.AMR = []string{"pwd"}
	if _, err := i.AuthenticateTechnician(context.Background(), "no-mfa"); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("no MFA: %v", err)
	}
	claims.AMR, claims.Aud = []string{"mfa"}, audience{"other"}
	if _, err := i.AuthenticateTechnician(context.Background(), "wrong-aud"); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("wrong audience: %v", err)
	}
	claims.Active = false
	if _, err := i.AuthenticateTechnician(context.Background(), "inactive"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("inactive: %v", err)
	}
}
