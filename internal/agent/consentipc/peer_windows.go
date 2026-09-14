//go:build windows

package consentipc

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// peer is who is on the other end of one pipe connection, established from
// the connection itself. Nothing the consent application says about itself
// is believed: the pipe names its process, the process names its image, its
// session and its user, and its token says whether it is elevated.
type peer struct {
	pid      uint32
	session  string
	user     string
	sid      string
	image    string
	elevated bool
}

// inspect verifies a connected peer. image is the installed consent
// executable, which lives in the ACL-protected program directory, so a
// process running from anywhere else is refused even if it is allowed to
// open the pipe. When requireSignature is set the image must also carry a
// valid Authenticode signature.
func inspect(conn net.Conn, image string, requireSignature bool) (peer, error) {
	h, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return peer{}, errors.New("consentipc: connection does not expose its pipe handle")
	}
	pipe := windows.Handle(h.Fd())
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &pid); err != nil {
		return peer{}, fmt.Errorf("consentipc: client process: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return peer{}, fmt.Errorf("consentipc: open client process %d: %w", pid, err)
	}
	defer windows.CloseHandle(proc)
	// The handle now keeps that process alive, so re-reading the pipe's
	// client narrows the window in which a recycled process ID could have
	// pointed the checks below at a different process.
	var again uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &again); err != nil || again != pid {
		return peer{}, fmt.Errorf("consentipc: client process changed under the connection: %w", err)
	}
	p := peer{pid: pid}
	if p.image, err = processImage(proc); err != nil {
		return peer{}, err
	}
	if !samePath(p.image, image) {
		return peer{}, fmt.Errorf("consentipc: %s is not the installed consent application (%s)", p.image, image)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
		return peer{}, fmt.Errorf("consentipc: client session: %w", err)
	}
	p.session = strconv.FormatUint(uint64(session), 10)
	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return peer{}, fmt.Errorf("consentipc: client token: %w", err)
	}
	defer token.Close()
	tu, err := token.GetTokenUser()
	if err != nil {
		return peer{}, fmt.Errorf("consentipc: client user: %w", err)
	}
	p.sid = tu.User.Sid.String()
	if account, domain, _, err := tu.User.Sid.LookupAccount(""); err == nil {
		p.user = account
		if domain != "" {
			p.user = domain + `\` + account
		}
	} else {
		p.user = p.sid
	}
	p.elevated = token.IsElevated()
	if requireSignature {
		if err := verifySignature(p.image); err != nil {
			return peer{}, err
		}
	}
	return p, nil
}

func processImage(proc windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(proc, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("consentipc: client image: %w", err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// samePath compares two Windows paths the way the filesystem does.
func samePath(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// sessionHasUser reports whether an OS session still has a signed-in user.
// It is how the service tells a consent application that crashed (pause)
// from a user who signed out (terminate the grants they approved).
func sessionHasUser(session string) bool {
	id, err := strconv.ParseUint(session, 10, 32)
	if err != nil {
		return false
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(uint32(id), &token); err != nil {
		return false
	}
	token.Close()
	return true
}

// interactiveSessions lists the OS sessions a person could answer in.
func interactiveSessions() []string {
	var count uint32
	var infos *windows.WTS_SESSION_INFO
	if err := windows.WTSEnumerateSessions(windows.Handle(0), 0, 1, &infos, &count); err != nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infos)))
	list := unsafe.Slice(infos, count)
	var out []string
	for _, s := range list {
		if s.State != windows.WTSActive && s.State != windows.WTSDisconnected {
			continue // a locked desktop is still Active; a listening station is not
		}
		id := strconv.FormatUint(uint64(s.SessionID), 10)
		if sessionHasUser(id) {
			out = append(out, id)
		}
	}
	return out
}

// launchInSession starts the consent application in one session, as the user
// signed in there. The installer also registers it to run at logon; this is
// what shows a request to somebody who closed their window.
func launchInSession(session, image string) error {
	id, err := strconv.ParseUint(session, 10, 32)
	if err != nil {
		return err
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(uint32(id), &token); err != nil {
		return fmt.Errorf("consentipc: session %s has no user: %w", session, err)
	}
	defer token.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return fmt.Errorf("consentipc: environment for session %s: %w", session, err)
	}
	defer windows.DestroyEnvironmentBlock(env)
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return err
	}
	cmd, err := windows.UTF16PtrFromString(`"` + image + `"`)
	if err != nil {
		return err
	}
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var pi windows.ProcessInformation
	const flags = windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_CONSOLE | windows.CREATE_DEFAULT_ERROR_MODE
	if err := windows.CreateProcessAsUser(token, nil, cmd, nil, nil, false, flags, env, nil, &si, &pi); err != nil {
		return fmt.Errorf("consentipc: start consent application in session %s: %w", session, err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

// Authenticode verification. Keyhole has no signing certificate yet, so this
// is off by default and switched on with KEYHOLE_REQUIRE_SIGNED_CONSENT_UI
// once one exists; see docs/CONSENTED-ACCESS.md.
var (
	modwintrust        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = modwintrust.NewProc("WinVerifyTrust")
)

type wintrustFileInfo struct {
	size         uint32
	filePath     *uint16
	file         windows.Handle
	knownSubject *windows.GUID
}

type wintrustData struct {
	size               uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	union              uintptr
	stateAction        uint32
	stateData          windows.Handle
	urlReference       *uint16
	provFlags          uint32
	uiContext          uint32
	signatureSettings  uintptr
}

const (
	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdSaferFlag             = 0x100
	wtdCacheOnlyURLRetrieval = 0x1000
)

// generic verify action, WINTRUST_ACTION_GENERIC_VERIFY_V2
var verifyActionGUID = windows.GUID{Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

// verifySignature reports whether path carries a valid Authenticode
// signature, with no user interface and no revocation fetch (the service has
// no desktop and must not block on the network).
func verifySignature(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	file := wintrustFileInfo{size: uint32(unsafe.Sizeof(wintrustFileInfo{})), filePath: p}
	data := wintrustData{
		size:             uint32(unsafe.Sizeof(wintrustData{})),
		uiChoice:         wtdUINone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      wtdChoiceFile,
		union:            uintptr(unsafe.Pointer(&file)),
		stateAction:      wtdStateActionVerify,
		provFlags:        wtdSaferFlag | wtdCacheOnlyURLRetrieval,
	}
	rc, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&verifyActionGUID)), uintptr(unsafe.Pointer(&data)))
	data.stateAction = wtdStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&verifyActionGUID)), uintptr(unsafe.Pointer(&data)))
	if rc != 0 {
		return fmt.Errorf("consentipc: %s is not validly signed (WinVerifyTrust 0x%x)", path, uint32(rc))
	}
	return nil
}
