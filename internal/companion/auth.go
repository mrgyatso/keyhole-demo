package companion

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/passkey"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Enrollment, sign-in and sign-out. A one-time link enrolls a passkey; the
// passkey signs the technician in; signing out locks their unlocked client
// and ends every sign-in they have. A sign-in only shows the technician's
// cards: each approval still takes a fresh assertion.

const (
	cookieName         = "keyhole_companion"
	rpName             = "Keyhole"
	maxPasskeyName     = 64
	defaultPasskeyName = "Passkey"
)

// errSignedOut is a request without a usable sign-in.
var errSignedOut = errors.New("companion: not signed in")

// userHandle is the WebAuthn user.id of a technician's passkeys. It is the
// same for every passkey of one technician, so an authenticator keeps a single
// Keyhole passkey for them, and it is not their name.
func userHandle(technician string) []byte {
	sum := sha256.Sum256([]byte("keyhole-user:" + technician))
	return sum[:16]
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"` // base64url
}

// descriptors lists the live passkeys among keys.
func descriptors(keys []model.Passkey) []credentialDescriptor {
	out := []credentialDescriptor{}
	for _, k := range keys {
		if k.Live() == nil {
			out = append(out, credentialDescriptor{Type: "public-key", ID: k.CredentialID})
		}
	}
	return out
}

type pubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type authenticatorSelection struct {
	ResidentKey        string `json:"residentKey"`
	RequireResidentKey bool   `json:"requireResidentKey"` // what browsers before residentKey read
	UserVerification   string `json:"userVerification"`
}

type relyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userEntity struct {
	ID          string `json:"id"` // base64url
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// creationOptions is PublicKeyCredentialCreationOptions, its binary members
// in base64url for the page to decode.
type creationOptions struct {
	Challenge              string                 `json:"challenge"`
	RP                     relyingParty           `json:"rp"`
	User                   userEntity             `json:"user"`
	PubKeyCredParams       []pubKeyCredParam      `json:"pubKeyCredParams"`
	AuthenticatorSelection authenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
	ExcludeCredentials     []credentialDescriptor `json:"excludeCredentials"`
	Timeout                int64                  `json:"timeout"` // milliseconds
}

// requestOptions is PublicKeyCredentialRequestOptions, likewise.
type requestOptions struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
	Timeout          int64                  `json:"timeout"`
}

// creationOptions asks for a discoverable ES256 passkey with user
// verification, and no attestation: the one-time link is what vouches for
// the technician. The technician's live passkeys are excluded, so one
// authenticator does not enroll twice.
func (s *Server) creationOptions(technician string, challenge []byte, existing []model.Passkey) creationOptions {
	return creationOptions{
		Challenge:              b64url(challenge),
		RP:                     relyingParty{ID: s.rpID, Name: rpName},
		User:                   userEntity{ID: b64url(userHandle(technician)), Name: technician, DisplayName: technician},
		PubKeyCredParams:       []pubKeyCredParam{{Type: "public-key", Alg: passkey.AlgES256}},
		AuthenticatorSelection: authenticatorSelection{ResidentKey: "required", RequireResidentKey: true, UserVerification: "required"},
		Attestation:            "none",
		ExcludeCredentials:     descriptors(existing),
		Timeout:                ceremonyHint.Milliseconds(),
	}
}

// requestOptions asks for an assertion with user verification, by one of
// allow, or by any Keyhole passkey on the device when allow is empty.
func (s *Server) requestOptions(challenge []byte, allow []model.Passkey) requestOptions {
	return requestOptions{Challenge: b64url(challenge), RPID: s.rpID, AllowCredentials: descriptors(allow),
		UserVerification: "required", Timeout: ceremonyHint.Milliseconds()}
}

func credentialOf(p model.Passkey) passkey.Credential {
	return passkey.Credential{ID: p.CredentialID, PublicKey: p.PublicKey, Algorithm: p.Algorithm, SignCount: p.SignCount}
}

type enrollBeginRequest struct {
	Token string `json:"token"`
}

type enrollBeginResponse struct {
	Technician string          `json:"technician"`
	Options    creationOptions `json:"options"`
}

type enrollFinishRequest struct {
	Token             string `json:"token"`
	CredentialID      string `json:"credential_id"`
	PublicKey         []byte `json:"public_key"`
	Algorithm         int    `json:"algorithm"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Name              string `json:"name"`
}

// assertionBegin is what every assertion ceremony's begin returns.
type assertionBegin struct {
	Ceremony string         `json:"ceremony,omitempty"`
	Options  requestOptions `json:"options"`
}

type loginFinishRequest struct {
	Ceremony string `json:"ceremony"`
	proto.PasskeyAssertion
}

type signInResponse struct {
	Technician string `json:"technician"`
	Passkey    string `json:"passkey"` // the name of the passkey signed in with
}

// enrollLink resolves a one-time enrollment secret, or answers why it
// cannot.
func (s *Server) enrollLink(w http.ResponseWriter, r *http.Request, secret string, now time.Time) (model.PasskeyLink, bool) {
	const again = " Ask your administrator for a new enrollment link."
	if !strings.HasPrefix(secret, model.SecretPasskeyLink+"_") {
		writeError(w, http.StatusNotFound, proto.ErrNotFound, "This is not a Keyhole enrollment link."+again)
		return model.PasskeyLink{}, false
	}
	link, err := s.store.PasskeyLinkByToken(r.Context(), secret, now)
	switch {
	case err == nil:
		return link, true
	case errors.Is(err, model.ErrNotFound):
		writeError(w, http.StatusNotFound, proto.ErrNotFound, "This enrollment link is not valid."+again)
	case errors.Is(err, model.ErrExhausted):
		writeError(w, http.StatusGone, codeExpired, "This enrollment link has already been used."+again)
	case errors.Is(err, model.ErrExpired):
		writeError(w, http.StatusGone, codeExpired, "This enrollment link has expired."+again)
	default:
		s.fail(w, err)
	}
	return model.PasskeyLink{}, false
}

func (s *Server) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	var req enrollBeginRequest
	if !decode(w, r, &req, false) {
		return
	}
	now := s.now()
	link, ok := s.enrollLink(w, r, req.Token, now)
	if !ok {
		return
	}
	existing, err := s.store.PasskeysForTechnician(r.Context(), link.Technician)
	if err != nil {
		s.fail(w, err)
		return
	}
	challenge := newChallenge()
	s.enrolls.put(link.ID, ceremony{challenge: challenge, technician: link.Technician, subject: link.ID, issued: now})
	writeJSON(w, http.StatusOK, enrollBeginResponse{Technician: link.Technician,
		Options: s.creationOptions(link.Technician, challenge, existing)})
}

// handleEnrollFinish verifies the new passkey against the challenge issued
// for this link, stores it while consuming the link in one transaction, and
// signs the technician in with it.
func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	var req enrollFinishRequest
	if !decode(w, r, &req, false) {
		return
	}
	now := s.now()
	link, ok := s.enrollLink(w, r, req.Token, now)
	if !ok {
		return
	}
	cer, ok := s.enrolls.take(link.ID, now)
	if !ok {
		writeError(w, http.StatusGone, codeExpired, "Creating the passkey took too long. Start again: the link works until it expires.")
		return
	}
	name, err := passkeyName(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
		return
	}
	cred, err := passkey.VerifyRegistration(s.rp, cer.challenge, passkey.Attestation{CredentialID: req.CredentialID,
		PublicKey: req.PublicKey, Algorithm: req.Algorithm, AuthenticatorData: req.AuthenticatorData, ClientDataJSON: req.ClientDataJSON})
	if err != nil {
		s.log.Info("passkey enrollment refused", "technician", link.Technician, "link", link.ID, "err", err)
		writeError(w, http.StatusForbidden, codeForbidden, "The new passkey was not accepted: "+err.Error())
		return
	}
	p := model.Passkey{CredentialID: cred.ID, Technician: link.Technician, PublicKey: cred.PublicKey, Algorithm: cred.Algorithm,
		SignCount: cred.SignCount, Name: name, CreatedAt: now.UTC()}
	switch err := s.store.UsePasskeyLink(r.Context(), link.ID, p, now); {
	case errors.Is(err, model.ErrConflict):
		writeError(w, http.StatusConflict, codeConflict, "This passkey is already enrolled. Sign in with it instead.")
		return
	case errors.Is(err, model.ErrExhausted), errors.Is(err, model.ErrExpired):
		writeError(w, http.StatusGone, codeExpired, "This enrollment link was used or expired a moment ago. Ask your administrator for a new one.")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.log.Info("passkey enrolled", "technician", p.Technician, "credential", p.CredentialID, "name", p.Name, "link", link.ID)
	if s.signIn(w, r, p, now) {
		writeJSON(w, http.StatusOK, signInResponse{Technician: p.Technician, Passkey: p.Name})
	}
}

// passkeyName cleans the name a technician gave a new passkey.
func passkeyName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	switch {
	case name == "":
		return defaultPasskeyName, nil
	case len(name) > maxPasskeyName:
		return "", fmt.Errorf("the passkey's name is longer than %d bytes", maxPasskeyName)
	case strings.ContainsFunc(name, unicode.IsControl):
		return "", errors.New("the passkey's name contains control characters")
	}
	return name, nil
}

// handleLoginBegin starts a discoverable sign-in: the device offers whichever
// Keyhole passkey it holds, so the page asks for no name first.
func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !decode(w, r, &struct{}{}, true) {
		return
	}
	id, challenge := newToken(), newChallenge()
	s.logins.put(id, ceremony{challenge: challenge, issued: s.now()})
	writeJSON(w, http.StatusOK, assertionBegin{Ceremony: id, Options: s.requestOptions(challenge, nil)})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req loginFinishRequest
	if !decode(w, r, &req, false) {
		return
	}
	ctx, now := r.Context(), s.now()
	cer, ok := s.logins.take(req.Ceremony, now)
	if !ok {
		writeError(w, http.StatusGone, codeExpired, "Signing in took too long. Try again.")
		return
	}
	p, err := s.store.Passkey(ctx, req.CredentialID)
	switch {
	case errors.Is(err, model.ErrNotFound):
		writeError(w, http.StatusUnauthorized, proto.ErrUnauthorized,
			"This passkey is not enrolled with Keyhole. Use the enrollment link your administrator sent you.")
		return
	case err != nil:
		s.fail(w, err)
		return
	case p.Live() != nil:
		writeError(w, http.StatusForbidden, codeForbidden, "This passkey has been revoked. Ask your administrator for a new enrollment link.")
		return
	case len(req.UserHandle) > 0 && !bytes.Equal(req.UserHandle, userHandle(p.Technician)):
		writeError(w, http.StatusUnauthorized, proto.ErrUnauthorized, "This passkey was not made for the technician it is enrolled to.")
		return
	}
	count, err := passkey.VerifyAssertion(s.rp, cer.challenge, credentialOf(p), req.PasskeyAssertion)
	if err != nil {
		s.log.Info("companion sign-in refused", "technician", p.Technician, "credential", p.CredentialID, "err", err)
		writeError(w, http.StatusUnauthorized, proto.ErrUnauthorized, "The passkey's signature was not accepted. Try again.")
		return
	}
	if err := s.store.TouchPasskey(ctx, p.CredentialID, count, now); err != nil {
		s.fail(w, err)
		return
	}
	if s.signIn(w, r, p, now) {
		s.log.Info("companion sign-in", "technician", p.Technician, "credential", p.CredentialID)
		writeJSON(w, http.StatusOK, signInResponse{Technician: p.Technician, Passkey: p.Name})
	}
}

// signIn starts a companion sign-in with passkey p and sets its cookie. Only
// the hash of the cookie's secret is stored.
func (s *Server) signIn(w http.ResponseWriter, r *http.Request, p model.Passkey, now time.Time) bool {
	secret := model.NewSecret(model.SecretCompanion)
	cs := model.CompanionSession{ID: model.NewID(model.PrefixCompanion), Technician: p.Technician, Credential: p.CredentialID,
		Hash: model.HashSecret(secret), CreatedAt: now.UTC(), ExpiresAt: now.Add(model.CompanionSessionTTL).UTC()}
	if err := s.store.CreateCompanionSession(r.Context(), cs); err != nil {
		s.fail(w, err)
		return false
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: secret, Path: "/", MaxAge: int(model.CompanionSessionTTL / time.Second),
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
	return true
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
}

// session resolves the request's sign-in. A sign-in lasts only as long as the
// passkey that made it: revoking the passkey signs out every device that
// signed in with it.
func (s *Server) session(r *http.Request) (model.CompanionSession, error) {
	c, err := r.Cookie(cookieName)
	if err != nil || !strings.HasPrefix(c.Value, model.SecretCompanion+"_") {
		return model.CompanionSession{}, errSignedOut
	}
	ctx := r.Context()
	cs, err := s.store.CompanionSessionByToken(ctx, c.Value)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return model.CompanionSession{}, errSignedOut
	case err != nil:
		return model.CompanionSession{}, err
	case cs.Valid(s.now()) != nil:
		return model.CompanionSession{}, errSignedOut
	}
	p, err := s.store.Passkey(ctx, cs.Credential)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return model.CompanionSession{}, errSignedOut
	case err != nil:
		return model.CompanionSession{}, err
	case p.Technician != cs.Technician || p.Live() != nil:
		return model.CompanionSession{}, errSignedOut
	}
	return cs, nil
}

// signedIn admits only requests with a usable sign-in, and hands it to h.
func (s *Server) signedIn(h func(http.ResponseWriter, *http.Request, model.CompanionSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cs, err := s.session(r)
		switch {
		case errors.Is(err, errSignedOut):
			writeError(w, http.StatusUnauthorized, proto.ErrUnauthorized, "Sign in with your passkey.")
			return
		case err != nil:
			s.fail(w, err)
			return
		}
		h(w, r, cs)
	}
}

// handleLogout ends the technician's unlocked access and every companion
// sign-in they have, on every device: that is what signing out means.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	if !decode(w, r, &struct{}{}, true) {
		return
	}
	ctx, cancel := s.gateContext(r)
	defer cancel()
	lockErr := s.gate.LockAll(ctx, cs.Technician, model.ReasonSignedOut)
	if lockErr != nil {
		s.log.Error("sign-out could not lock the technician's unlocks", "technician", cs.Technician, "err", lockErr)
	}
	if err := s.store.RevokeCompanionSessions(ctx, cs.Technician, s.now()); err != nil {
		// The sign-in still works, so the cookie stays and signing out can be
		// tried again.
		s.log.Error("sign-out could not end the technician's sign-ins", "technician", cs.Technician, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "Keyhole could not sign you out. Try again.")
		return
	}
	s.clearCookie(w)
	if lockErr != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrInternal,
			"You are signed out, but Keyhole could not lock your unlocked client. Sign in again and press Lock.")
		return
	}
	s.log.Info("companion sign-out", "technician", cs.Technician)
	writeJSON(w, http.StatusOK, map[string]bool{"signed_out": true})
}
