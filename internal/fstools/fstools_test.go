package fstools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

var fixedNow = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

// tempRoot returns a fresh temp dir by its canonical path. On macOS the
// temp dir sits behind the /var -> /private/var symlink.
func tempRoot(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
}

func testPolicy(rules ...proto.AllowRule) proto.Policy {
	return proto.Policy{
		Version:        1,
		Allow:          rules,
		MaxReadBytes:   policy.DefaultMaxReadBytes,
		MaxFileBytes:   policy.DefaultMaxFileBytes,
		MaxListEntries: policy.DefaultMaxListEntries,
		MaxMatches:     policy.DefaultMaxMatches,
	}
}

func rootRule(root string, files ...string) proto.AllowRule {
	return proto.AllowRule{ID: "test-root", Path: root, Files: files}
}

func request(t *testing.T, op string, args any, pol proto.Policy) *proto.Request {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return &proto.Request{V: proto.Version, ID: "req_test", Op: op, Args: raw, Policy: pol,
		Caller: proto.Caller{Tech: "tester", Session: "ses_test"}, Deadline: time.Now().Add(time.Minute)}
}

func run(t *testing.T, x *Executor, op string, args any, pol proto.Policy) *proto.Response {
	t.Helper()
	return x.Execute(context.Background(), request(t, op, args, pol))
}

func result[T any](t *testing.T, resp *proto.Response) T {
	t.Helper()
	if !resp.OK || resp.Error != nil {
		t.Fatalf("call failed: %+v", resp.Error)
	}
	var v T
	if err := json.Unmarshal(resp.Result, &v); err != nil {
		t.Fatalf("decoding result %s: %v", resp.Result, err)
	}
	return v
}

func wantError(t *testing.T, resp *proto.Response, code string) {
	t.Helper()
	if resp.OK || resp.Error == nil || resp.Error.Code != code {
		t.Fatalf("got ok=%v error=%+v; want error %s", resp.OK, resp.Error, code)
	}
	if resp.Error.Message == "" {
		t.Errorf("error %s has no message", code)
	}
	if len(resp.Result) != 0 || resp.Meta.Bytes != 0 || resp.Meta.SHA256 != "" {
		t.Errorf("failed call carried content: %d bytes, sha %q", len(resp.Result), resp.Meta.SHA256)
	}
}

// fakeRedactor stands in for the gitleaks-backed redactor.
type fakeRedactor struct{ secret string }

func (f fakeRedactor) Redact(s string) (string, int, []string) {
	n := strings.Count(s, f.secret)
	if n == 0 {
		return s, 0, nil
	}
	return strings.ReplaceAll(s, f.secret, "[REDACTED:test-secret]"), n, []string{"test-secret"}
}

func TestExecuteAnswersUnsupportedOpsWithAnEnvelope(t *testing.T) {
	x := New(Options{AgentVersion: "test-1.0", Now: func() time.Time { return fixedNow }})
	for _, op := range []string{proto.OpPing, "write_file", "delete", ""} {
		resp := x.Execute(context.Background(), &proto.Request{V: proto.Version, ID: "req_1", Op: op})
		wantError(t, resp, proto.ErrUnsupported)
		if resp.V != proto.Version || resp.ID != "req_1" {
			t.Errorf("op %q: envelope v=%d id=%q", op, resp.V, resp.ID)
		}
		if resp.Meta.AgentVersion != "test-1.0" || !resp.Meta.AgentTime.Equal(fixedNow) {
			t.Errorf("op %q: meta %+v", op, resp.Meta)
		}
	}
}

func TestExecuteRejectsOtherProtocolVersions(t *testing.T) {
	root := tempRoot(t)
	req := request(t, proto.OpStat, proto.StatArgs{Path: root}, testPolicy(rootRule(root)))
	req.V = proto.Version + 1
	wantError(t, New(Options{}).Execute(context.Background(), req), proto.ErrBadRequest)
}

func TestExecuteRejectsMissingOrMalformedArgs(t *testing.T) {
	root := tempRoot(t)
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	for name, raw := range map[string]json.RawMessage{
		"missing":   nil,
		"not json":  json.RawMessage(`{"path":`),
		"no path":   json.RawMessage(`{}`),
		"wrong typ": json.RawMessage(`{"path": 7}`),
	} {
		req := request(t, proto.OpStat, nil, pol)
		req.Args = raw
		resp := x.Execute(context.Background(), req)
		if resp.Error == nil || resp.Error.Code != proto.ErrBadRequest {
			t.Errorf("%s: got %+v; want bad_request", name, resp.Error)
		}
	}
}

func TestRedactionWithoutARedactorFailsClosed(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "app.log"), "password=hunter2\n")
	pol := testPolicy(rootRule(root))
	pol.Redact = true
	x := New(Options{}) // no Redactor
	for op, args := range map[string]any{
		proto.OpReadFile:    proto.ReadFileArgs{Path: filepath.Join(root, "app.log")},
		proto.OpGrep:        proto.GrepArgs{Path: root, Pattern: "password"},
		proto.OpStat:        proto.StatArgs{Path: root},
		proto.OpListDir:     proto.ListDirArgs{Path: root},
		proto.OpSearchFiles: proto.SearchFilesArgs{Path: root, Pattern: "*"},
		proto.OpHashFile:    proto.HashFileArgs{Path: filepath.Join(root, "app.log")},
	} {
		resp := run(t, x, op, args, pol)
		if resp.OK || resp.Error == nil || resp.Error.Code != proto.ErrInternal || len(resp.Result) != 0 {
			t.Errorf("%s: got ok=%v err=%+v result=%s; want internal with no result", op, resp.OK, resp.Error, resp.Result)
		}
	}
}

func TestExecuteHonoursDeadlineAndCancellation(t *testing.T) {
	root := tempRoot(t)
	x := New(Options{})
	req := request(t, proto.OpStat, proto.StatArgs{Path: root}, testPolicy(rootRule(root)))
	req.Deadline = time.Now().Add(-time.Second)
	wantError(t, x.Execute(context.Background(), req), proto.ErrTimeout)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req = request(t, proto.OpStat, proto.StatArgs{Path: root}, testPolicy(rootRule(root)))
	wantError(t, x.Execute(ctx, req), proto.ErrTimeout)
}
