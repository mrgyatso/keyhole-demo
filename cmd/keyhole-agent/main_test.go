package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
)

func TestInstallPassesTokenOnlyToEnrollment(t *testing.T) {
	var out, errOut bytes.Buffer
	a := newApplication(&out, &errOut)
	const secret = "khe_acme_test_secret_not_for_logs"
	a.getenv = func(key string) string {
		if key == enrollTokenEnv {
			return secret
		}
		return ""
	}
	a.gather = func(context.Context) (hostinfo.Info, error) {
		return hostinfo.Info{Hostname: "test", MachineID: "test", OS: "windows", Arch: "amd64"}, nil
	}
	a.status = func(context.Context) (serviceState, error) { return serviceState{}, nil }
	var enrolled, installed bool
	a.enroll = func(_ context.Context, o agent.EnrollOptions) (*agent.Enrollment, error) {
		enrolled = true
		if o.Token != secret || o.Org != "acme" {
			t.Fatal("enrollment arguments lost")
		}
		return &agent.Enrollment{DeviceID: "dev_test", Client: "acme"}, nil
	}
	a.install = func(_ context.Context, source string, data agent.DataDir) error {
		if !enrolled {
			t.Fatal("install before enrollment")
		}
		installed = true
		return nil
	}
	if err := a.run(context.Background(), []string{"install", "--url", "https://keyhole.test", "--org", "acme", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("service not installed")
	}
	if strings.Contains(out.String()+errOut.String(), secret) {
		t.Fatal("token leaked in command output")
	}
}

func TestInstallDoesNotReenrollExistingService(t *testing.T) {
	a := newApplication(&bytes.Buffer{}, &bytes.Buffer{})
	a.getenv = func(string) string { return "test-token" }
	a.status = func(context.Context) (serviceState, error) { return serviceState{Installed: true}, nil }
	a.enroll = func(context.Context, agent.EnrollOptions) (*agent.Enrollment, error) {
		t.Fatal("existing service reenrolled")
		return nil, nil
	}
	if err := a.run(context.Background(), []string{"install", "--url", "https://keyhole.test"}); err == nil {
		t.Fatal("existing installation accepted")
	}
}

func TestFailedEnrollmentDoesNotInstallService(t *testing.T) {
	a := newApplication(&bytes.Buffer{}, &bytes.Buffer{})
	a.getenv = func(string) string { return "test-token" }
	a.status = func(context.Context) (serviceState, error) { return serviceState{}, nil }
	a.gather = func(context.Context) (hostinfo.Info, error) { return hostinfo.Info{}, nil }
	a.enroll = func(context.Context, agent.EnrollOptions) (*agent.Enrollment, error) {
		return nil, errors.New("enrollment refused")
	}
	a.install = func(context.Context, string, agent.DataDir) error {
		t.Fatal("installed after enrollment failed")
		return nil
	}
	if err := a.run(context.Background(), []string{"install", "--url", "https://keyhole.test"}); err == nil {
		t.Fatal("enrollment failure ignored")
	}
}

func TestCopyExecutableRefusesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyExecutable(src, dst); err == nil {
		t.Fatal("existing destination overwritten")
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "existing" {
		t.Fatal("existing executable changed")
	}
}
