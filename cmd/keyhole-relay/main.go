package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/companion"
	"github.com/mrgyatso/keyhole/internal/gateway"
	"github.com/mrgyatso/keyhole/internal/identity"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/relay"
	"github.com/mrgyatso/keyhole/internal/store"
)

const (
	configFile        = "relay.json"
	databaseFile      = "keyhole.db"
	secretsDir        = "secrets"
	operatorFile      = "operator.json"
	sysCredsFile      = "sys.creds"
	downloadDir       = "dl"
	defaultNATSURL    = "nats://127.0.0.1:4222"
	defaultPublic     = "127.0.0.1:7801"
	defaultPrivate    = "127.0.0.1:7802"
	defaultCompanion  = "127.0.0.1:7803"
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
)

// diskConfig contains only deployment settings. Authentication material is
// kept in owner-only files under secrets/, and API secrets are stored only as
// hashes in SQLite.
type diskConfig struct {
	PublicURL         string `json:"public_url"`
	NATSWSURL         string `json:"nats_ws_url"`
	MCPURL            string `json:"mcp_url"`
	NATSDir           string `json:"nats_dir"`
	NATSClientListen  string `json:"nats_client_listen"`
	NATSWSListen      string `json:"nats_ws_listen"`
	NATSMonitorListen string `json:"nats_monitor_listen"`
	NATSURL           string `json:"nats_url"`
	PublicListen      string `json:"public_listen"`
	PrivateListen     string `json:"private_listen"`
}

type paths struct {
	data, config, database, secrets, operator, sysCreds, downloads string
}

func dataPaths(data string) paths {
	return paths{
		data:      data,
		config:    filepath.Join(data, configFile),
		database:  filepath.Join(data, databaseFile),
		secrets:   filepath.Join(data, secretsDir),
		operator:  filepath.Join(data, secretsDir, operatorFile),
		sysCreds:  filepath.Join(data, secretsDir, sysCredsFile),
		downloads: filepath.Join(data, downloadDir),
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "keyhole-relay:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		usage(errOut)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], out, errOut)
	case "serve":
		return runServe(ctx, args[1:], errOut)
	case "help", "-h", "--help":
		usage(out)
		return nil
	default:
		usage(errOut)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  keyhole-relay init --data DIR --public-url URL --nats-ws-url URL --mcp-url URL [--nats-dir DIR] [--force]")
	fmt.Fprintln(w, "  keyhole-relay serve --data DIR [--nats-url URL] [--public-listen ADDR] [--private-listen ADDR]")
}

func runInit(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(errOut)
	data := fs.String("data", "", "relay data directory")
	publicURL := fs.String("public-url", "", "public enrollment URL")
	natsWSURL := fs.String("nats-ws-url", "", "agent-facing NATS WebSocket URL")
	mcpURL := fs.String("mcp-url", "", "private MCP endpoint URL")
	natsDir := fs.String("nats-dir", "", "nats-server data directory (default DIR/nats)")
	natsClientListen := fs.String("nats-client-listen", natsauth.DefaultClientListen, "nats-server client listen address")
	natsWSListen := fs.String("nats-ws-listen", natsauth.DefaultWSListen, "nats-server WebSocket listen address")
	natsMonitorListen := fs.String("nats-monitor-listen", natsauth.DefaultMonitorListen, "nats-server monitor listen address")
	force := fs.Bool("force", false, "update an existing initialization without rotating secrets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init: unexpected argument %q", fs.Arg(0))
	}
	if *data == "" || *publicURL == "" || *natsWSURL == "" || *mcpURL == "" {
		return errors.New("init requires --data, --public-url, --nats-ws-url, and --mcp-url")
	}
	dataAbs, err := filepath.Abs(*data)
	if err != nil {
		return fmt.Errorf("init: data directory: %w", err)
	}
	if *natsDir == "" {
		*natsDir = filepath.Join(dataAbs, "nats")
	}
	natsAbs, err := filepath.Abs(*natsDir)
	if err != nil {
		return fmt.Errorf("init: nats directory: %w", err)
	}
	if err := validateURL(*publicURL, "public-url", "https", "http"); err != nil {
		return err
	}
	if err := validateURL(*natsWSURL, "nats-ws-url", "wss", "ws"); err != nil {
		return err
	}
	if err := validateURL(*mcpURL, "mcp-url", "https", "http"); err != nil {
		return err
	}

	cfg := diskConfig{
		PublicURL:         strings.TrimRight(*publicURL, "/"),
		NATSWSURL:         *natsWSURL,
		MCPURL:            *mcpURL,
		NATSDir:           natsAbs,
		NATSClientListen:  *natsClientListen,
		NATSWSListen:      *natsWSListen,
		NATSMonitorListen: *natsMonitorListen,
		NATSURL:           defaultNATSURL,
		PublicListen:      defaultPublic,
		PrivateListen:     defaultPrivate,
	}
	adminToken, created, err := initialize(dataPaths(dataAbs), cfg, *force)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "initialized Keyhole relay in %s\n", dataAbs)
	if created {
		fmt.Fprintf(out, "admin token (shown once): %s\n", adminToken)
	} else {
		fmt.Fprintln(out, "admin token unchanged")
	}
	return nil
}

func initialize(p paths, cfg diskConfig, force bool) (adminToken string, created bool, err error) {
	if _, err := os.Stat(p.config); err == nil && !force {
		return "", false, fmt.Errorf("init: %s already exists (use --force to update settings without rotating secrets)", p.config)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("init: %w", err)
	}
	for _, d := range []string{p.data, p.secrets} {
		if err := privateDir(d); err != nil {
			return "", false, err
		}
	}
	if err := os.MkdirAll(p.downloads, 0o755); err != nil {
		return "", false, fmt.Errorf("init: downloads directory: %w", err)
	}

	op, err := loadOrCreateOperator(p, force)
	if err != nil {
		return "", false, err
	}
	if err := writeOrKeepSysCreds(p.sysCreds, op, force); err != nil {
		return "", false, err
	}
	if err := writeNATSFiles(op, cfg, force); err != nil {
		return "", false, err
	}

	st, err := store.Open(p.database)
	if err != nil {
		return "", false, err
	}
	defer st.Close()
	if _, err := st.AdminTokenHash(context.Background()); errors.Is(err, model.ErrNotFound) {
		adminToken = model.NewSecret(model.SecretAdmin)
		if err := st.SetAdminTokenHash(context.Background(), model.HashSecret(adminToken), time.Now().UTC()); err != nil {
			return "", false, err
		}
		created = true
	} else if err != nil {
		return "", false, err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", false, fmt.Errorf("init: config: %w", err)
	}
	if err := writeAtomic(p.config, append(b, '\n'), 0o600, !force); err != nil {
		return "", false, fmt.Errorf("init: config: %w", err)
	}
	return adminToken, created, nil
}

func loadOrCreateOperator(p paths, force bool) (*natsauth.Operator, error) {
	op, err := natsauth.LoadOperator(p.operator)
	if err == nil {
		if !force {
			return nil, fmt.Errorf("init: %s already exists", p.operator)
		}
		return op, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		return nil, err
	}
	if force {
		if _, dbErr := os.Stat(p.database); dbErr == nil {
			return nil, fmt.Errorf("init: refusing to create a new operator for existing database %s", p.database)
		}
	}
	op, err = natsauth.NewOperator("keyhole")
	if err != nil {
		return nil, err
	}
	if err := op.WriteFile(p.operator); err != nil {
		return nil, err
	}
	return op, nil
}

func writeOrKeepSysCreds(path string, op *natsauth.Operator, force bool) error {
	if _, err := os.Stat(path); err == nil {
		if !force {
			return fmt.Errorf("init: %s already exists", path)
		}
		_, err = natsauth.ReadCreds(path)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	creds, err := op.NewSysUser("keyhole-relay")
	if err != nil {
		return err
	}
	b, err := creds.Marshal()
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0o600, true)
}

func writeNATSFiles(op *natsauth.Operator, disk diskConfig, force bool) error {
	cfg := natsauth.ServerConfig{
		Dir: disk.NATSDir, ClientListen: disk.NATSClientListen,
		WSListen: disk.NATSWSListen, MonitorListen: disk.NATSMonitorListen,
	}
	if !force {
		return natsauth.WriteServerDir(op, cfg)
	}
	for _, d := range []string{disk.NATSDir, filepath.Join(disk.NATSDir, natsauth.ResolverDir), filepath.Join(disk.NATSDir, natsauth.JetStreamDir)} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	conf, err := op.ServerConf(cfg)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(disk.NATSDir, natsauth.OperatorJWTFile), []byte(op.JWT+"\n"), 0o600, false); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(disk.NATSDir, natsauth.ConfFile), conf, 0o600, false)
}

func validateURL(raw, flagName string, schemes ...string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("init: --%s must be an absolute URL without credentials, query, or fragment", flagName)
	}
	for _, scheme := range schemes {
		if u.Scheme == scheme {
			return nil
		}
	}
	return fmt.Errorf("init: --%s must use %s", flagName, strings.Join(schemes, " or "))
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure %s: %w", path, err)
		}
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode, exclusive bool) error {
	if exclusive {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func runServe(ctx context.Context, args []string, errOut io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	data := fs.String("data", "", "relay data directory")
	natsURL := fs.String("nats-url", "", "relay-facing NATS URL")
	publicListen := fs.String("public-listen", "", "public HTTP listen address")
	privateListen := fs.String("private-listen", "", "private HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("serve: unexpected argument %q", fs.Arg(0))
	}
	if *data == "" {
		return errors.New("serve requires --data")
	}
	dataAbs, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	p := dataPaths(dataAbs)
	cfg, err := loadDiskConfig(p.config)
	if err != nil {
		return err
	}
	if *natsURL != "" {
		cfg.NATSURL = *natsURL
	}
	if *publicListen != "" {
		cfg.PublicListen = *publicListen
	}
	if *privateListen != "" {
		cfg.PrivateListen = *privateListen
	}
	if cfg.PublicListen == cfg.PrivateListen {
		return errors.New("serve: public and private listeners must be different")
	}
	log := slog.New(slog.NewJSONHandler(errOut, nil))
	rt, err := newRuntime(p, cfg, log)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.Serve(ctx, cfg.PublicListen, cfg.PrivateListen)
}

func loadDiskConfig(path string) (diskConfig, error) {
	if err := requirePrivateFile(path); err != nil {
		return diskConfig{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return diskConfig{}, fmt.Errorf("serve: config: %w", err)
	}
	var cfg diskConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("serve: config: %w", err)
	}
	if cfg.NATSURL == "" {
		cfg.NATSURL = defaultNATSURL
	}
	if cfg.PublicListen == "" {
		cfg.PublicListen = defaultPublic
	}
	if cfg.PrivateListen == "" {
		cfg.PrivateListen = defaultPrivate
	}
	if cfg.NATSWSURL == "" || cfg.MCPURL == "" {
		return cfg, errors.New("serve: relay.json is missing nats_ws_url or mcp_url")
	}
	return cfg, nil
}

type runtimeServer struct {
	store           *store.Store
	conns           *relay.ConnManager
	relay           *relay.Server
	gateway         *gateway.Gateway
	public, private http.Handler
	// companion is served on companionListen alone; nil when technician
	// approval is off.
	companion       http.Handler
	companionListen string
}

func newRuntime(p paths, cfg diskConfig, log *slog.Logger) (*runtimeServer, error) {
	for _, path := range []string{p.config, p.operator, p.sysCreds, p.database} {
		if err := requirePrivateFile(path); err != nil {
			return nil, err
		}
	}
	op, err := natsauth.LoadOperator(p.operator)
	if err != nil {
		return nil, err
	}
	sys, err := natsauth.ReadCreds(p.sysCreds)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(p.database)
	if err != nil {
		return nil, err
	}
	conns := relay.NewConnManager(cfg.NATSURL, st, log)
	aud := audit.NewJetStreamStore(conns, audit.WithLogger(log))
	auth, err := technicianAuthenticatorFromEnv()
	var companionOrigin, companionListen string
	if err == nil {
		companionOrigin, companionListen, err = companionFromEnv()
	}
	if err != nil {
		conns.Close()
		st.Close()
		return nil, err
	}
	// Technician approval (Slice 6) is on exactly when the companion has an
	// origin to be served at. Without one, access requests keep the Slice 3
	// endpoint-consent flow.
	var approvals model.ApprovalStore
	if companionOrigin != "" {
		approvals = st
	}
	gw, err := gateway.New(gateway.Config{Directory: st, TechnicianACL: st, Authenticator: auth, Access: st,
		Approvals: approvals, CompanionURL: companionOrigin, Conns: conns, Audit: aud, Logger: log})
	if err != nil {
		conns.Close()
		st.Close()
		return nil, err
	}
	var companionHandler http.Handler
	if companionOrigin != "" {
		c, err := companion.New(companion.Config{Store: st, Directory: st, Gate: gw, Origin: companionOrigin, Logger: log})
		if err != nil {
			conns.Close()
			st.Close()
			return nil, fmt.Errorf("serve: %w", err)
		}
		companionHandler = c.Handler()
	}
	reports := map[string]relay.ReportWriter{
		"csv": func(w io.Writer, _ relay.ReportMeta, entries []audit.Entry, _ audit.VerifyResult) error {
			return audit.WriteCSV(w, entries)
		},
		"pdf": func(w io.Writer, m relay.ReportMeta, entries []audit.Entry, v audit.VerifyResult) error {
			return audit.WritePDF(w, audit.ReportMeta{
				Client: m.Client, ClientName: m.ClientName, From: m.From, To: m.To, GeneratedAt: m.GeneratedAt,
			}, entries, v)
		},
	}
	srv, err := relay.New(relay.Config{
		Store: st, Conns: conns, Operator: op, SysCreds: sys, Audit: aud,
		AgentNATSURLs: []string{cfg.NATSWSURL}, MCPURL: cfg.MCPURL,
		DownloadDir: p.downloads, MCP: gw.Handler(), CompanionURL: companionOrigin, Reports: reports, Logger: log,
	})
	if err != nil {
		conns.Close()
		st.Close()
		return nil, err
	}
	return &runtimeServer{store: st, conns: conns, relay: srv, gateway: gw, public: srv.PublicHandler(), private: srv.PrivateHandler(),
		companion: companionHandler, companionListen: companionListen}, nil
}

// companionFromEnv reads the companion's settings (Slice 6).
// KEYHOLE_COMPANION_ORIGIN is the origin technicians open, e.g.
// https://library.example.ts.net, and turns technician approval on.
// KEYHOLE_COMPANION_LISTEN is where the relay serves it, behind the HTTPS
// proxy that owns that origin.
func companionFromEnv() (origin, listen string, err error) {
	origin = strings.TrimRight(strings.TrimSpace(os.Getenv("KEYHOLE_COMPANION_ORIGIN")), "/")
	listen = strings.TrimSpace(os.Getenv("KEYHOLE_COMPANION_LISTEN"))
	switch {
	case origin == "" && listen != "":
		return "", "", errors.New("serve: KEYHOLE_COMPANION_LISTEN is set without KEYHOLE_COMPANION_ORIGIN")
	case origin == "":
		return "", "", nil
	case listen == "":
		listen = defaultCompanion
	}
	return origin, listen, nil
}

func technicianAuthenticatorFromEnv() (model.TechnicianAuthenticator, error) {
	endpoint := strings.TrimSpace(os.Getenv("KEYHOLE_OAUTH_INTROSPECTION_URL"))
	clientID := strings.TrimSpace(os.Getenv("KEYHOLE_OAUTH_CLIENT_ID"))
	clientSecret := os.Getenv("KEYHOLE_OAUTH_CLIENT_SECRET")
	audience := strings.TrimSpace(os.Getenv("KEYHOLE_OAUTH_AUDIENCE"))
	if endpoint == "" && clientID == "" && clientSecret == "" && audience == "" {
		return nil, nil
	}
	auth, err := identity.NewIntrospector(identity.Config{Endpoint: endpoint, ClientID: clientID,
		ClientSecret: clientSecret, Audience: audience})
	if err != nil {
		return nil, fmt.Errorf("serve: technician OAuth: %w", err)
	}
	return auth, nil
}

func (r *runtimeServer) Close() {
	r.relay.Close()
	r.conns.Close()
	_ = r.store.Close()
}

func (r *runtimeServer) Serve(ctx context.Context, publicAddr, privateAddr string) error {
	if r.companion != nil && (r.companionListen == publicAddr || r.companionListen == privateAddr) {
		return errors.New("serve: the companion needs a listener of its own, apart from the public and private ones")
	}
	pub, err := net.Listen("tcp", publicAddr)
	if err != nil {
		return fmt.Errorf("serve: public listen %s: %w", publicAddr, err)
	}
	priv, err := net.Listen("tcp", privateAddr)
	if err != nil {
		pub.Close()
		return fmt.Errorf("serve: private listen %s: %w", privateAddr, err)
	}
	listeners, handlers := []net.Listener{pub, priv}, []http.Handler{r.public, r.private}
	if r.companion != nil {
		comp, err := net.Listen("tcp", r.companionListen)
		if err != nil {
			pub.Close()
			priv.Close()
			return fmt.Errorf("serve: companion listen %s: %w", r.companionListen, err)
		}
		listeners, handlers = append(listeners, comp), append(handlers, r.companion)
	}
	if err := r.relay.Start(ctx); err != nil {
		for _, l := range listeners {
			l.Close()
		}
		return err
	}
	if r.gateway != nil {
		go r.gateway.Run(ctx)
	}
	servers := make([]*http.Server, len(listeners))
	errCh := make(chan error, len(listeners))
	for i, l := range listeners {
		servers[i] = &http.Server{Handler: handlers[i], ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: 2 * time.Minute}
		go func() { errCh <- servers[i].Serve(l) }()
	}
	select {
	case <-ctx.Done():
	case err = <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			err = fmt.Errorf("serve: http server: %w", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		if shutdownErr := srv.Shutdown(shutdownCtx); err == nil && shutdownErr != nil {
			err = shutdownErr
		}
	}
	return err
}

func requirePrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("serve: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("serve: %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("serve: %s is readable or writable by other users (mode %04o)", path, info.Mode().Perm())
	}
	return nil
}
