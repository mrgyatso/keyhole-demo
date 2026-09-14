// Package natsauthtest runs an embedded nats-server from the configuration
// natsauth generates, for tests.
package natsauthtest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"

	"github.com/mrgyatso/keyhole/internal/natsauth"
)

// LogEnv, when set in the environment, turns on the embedded server's debug
// log (to stderr).
const LogEnv = "KEYHOLE_TEST_NATS_LOG"

// StartServer writes op's nats-server files into a temp dir, with every
// listener on 127.0.0.1 and a random port, and runs the server until the
// test ends.
func StartServer(tb testing.TB, op *natsauth.Operator) *server.Server {
	tb.Helper()
	dir := tb.TempDir()
	err := natsauth.WriteServerDir(op, natsauth.ServerConfig{
		Dir:           dir,
		ClientListen:  "127.0.0.1:-1",
		WSListen:      "127.0.0.1:-1",
		MonitorListen: "127.0.0.1:-1",
		MaxFileStore:  16 * natsauth.AccountDiskQuota, // a limit, not an allocation
	})
	if err != nil {
		tb.Fatal(err)
	}
	return StartFromConfig(tb, filepath.Join(dir, natsauth.ConfFile), nil)
}

// StartFromConfig runs nats-server from a config file. adjust, if not nil,
// may change the parsed options before the server starts (e.g. to move
// listeners to random ports).
func StartFromConfig(tb testing.TB, confPath string, adjust func(*server.Options)) *server.Server {
	tb.Helper()
	opts, err := server.ProcessConfigFile(confPath)
	if err != nil {
		tb.Fatalf("parse %s: %v", confPath, err)
	}
	opts.NoLog, opts.NoSigs = true, true
	if os.Getenv(LogEnv) != "" {
		opts.NoLog, opts.Debug = false, true
	}
	if adjust != nil {
		adjust(opts)
	}
	s, err := server.NewServer(opts)
	if err != nil {
		tb.Fatalf("nats-server: %v", err)
	}
	s.ConfigureLogger()
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		s.Shutdown()
		tb.Fatal("nats-server did not become ready")
	}
	tb.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return s
}
