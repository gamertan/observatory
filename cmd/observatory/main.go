// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	obsagent "gamertan.com/observatory/internal/agent"
	"gamertan.com/observatory/internal/agentclient"
	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/httpserver"
	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/schema"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/observatory/internal/version"
	"gamertan.com/observatory/internal/webpush"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/organizations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "observatory:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		if address := os.Getenv("OBSERVATORY_TEND_CANDIDATE_LISTEN"); address != "" {
			return serveTendCandidate(address)
		}
		return errors.New("command required: check, server, agent, admin, migrate, query, export, import, version")
	}
	switch args[0] {
	case "version":
		fs := flag.NewFlagSet("version", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "print machine-readable version information")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		info := version.Current()
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		fmt.Printf("observatory %s (%s, %s)\n", info.Version, info.Commit, info.Go)
		return nil
	case "check":
		cfg, err := commandConfig(args[0], args[1:])
		if err != nil {
			return err
		}
		processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
		if err != nil {
			return err
		}
		defer processLock.Close()
		store, err := storage.Open(cfg.DataDir)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.Recover(context.Background()); err != nil {
			return err
		}
		identities, err := identity.Open(cfg.DataDir)
		if err != nil {
			return err
		}
		defer identities.Close()
		fmt.Println("ok")
		return nil
	case "migrate":
		return migrateCommand(args[1:])
	case "server":
		cfg, err := commandConfig("server", args[1:])
		if err != nil {
			return err
		}
		return serve(cfg)
	case "admin":
		return adminCommand(args[1:])
	case "agent":
		return agentCommand(args[1:])
	case "query":
		return queryCommand(args[1:])
	case "export":
		return exportCommand(args[1:])
	case "import":
		return importCommand(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serveTendCandidate(value string) error {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return errors.New("OBSERVATORY_TEND_CANDIDATE_LISTEN must be a loopback IP address with a nonzero port")
	}
	server := &http.Server{
		Addr:              address.String(),
		Handler:           tendCandidateHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	select {
	case listenErr := <-result:
		if errors.Is(listenErr, http.ErrServerClosed) {
			return nil
		}
		return listenErr
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func tendCandidateHandler() http.Handler {
	const marker = "Gamertan Observatory candidate\n"
	plain := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, body)
			}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", plain("ok\n"))
	mux.HandleFunc("HEAD /healthz", plain("ok\n"))
	mux.HandleFunc("GET /readyz", plain("ready\n"))
	mux.HandleFunc("HEAD /readyz", plain("ready\n"))
	mux.HandleFunc("GET /{$}", plain(marker))
	mux.HandleFunc("HEAD /{$}", plain(marker))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func exportCommand(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow a non-root config owner for local development")
	actor := fs.String("actor-user-id", "", "authorized user exporting the dashboard")
	organizationID := fs.String("organization-id", "", "organization identifier")
	dashboard := fs.String("dashboard", "", "dashboard slug")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("export accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	scope := access.Scope{OrganizationID: *organizationID}
	if err = identities.ValidateResourceScope(context.Background(), scope); err != nil {
		return err
	}
	decision, err := identities.Access.Authorize(context.Background(), *actor, scope, identity.PermissionDashboardsRead)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to export dashboards for the requested organization")
	}
	bundle, err := store.ExportDashboard(context.Background(), *organizationID, *dashboard)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bundle)
}

func importCommand(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow a non-root config owner for local development")
	actor := fs.String("actor-user-id", "", "authorized user importing the dashboard")
	organizationID := fs.String("organization-id", "", "destination organization identifier")
	approveOrganization := fs.String("approve-organization", "", "exact destination organization identifier approving the import")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("import accepts no positional arguments; provide one dashboard bundle on stdin")
	}
	if *organizationID == "" || *approveOrganization != *organizationID {
		return errors.New("dashboard import requires the exact organization identifier in approve-organization")
	}
	bundle, err := readDashboardBundle(os.Stdin)
	if err != nil {
		return err
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	scope := access.Scope{OrganizationID: *organizationID}
	if err = identities.ValidateResourceScope(context.Background(), scope); err != nil {
		return err
	}
	decision, err := identities.Access.Authorize(context.Background(), *actor, scope, identity.PermissionDashboardsManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to import dashboards for the requested organization")
	}
	for _, definition := range bundle.SavedQueries {
		requested := access.Scope{OrganizationID: *organizationID, ProjectID: definition.Scope.ProjectID, EnvironmentID: definition.Scope.EnvironmentID, ServiceID: definition.Scope.ServiceID}
		if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
			return errors.New("dashboard import references an unavailable resource scope")
		}
	}
	imported, err := store.ImportDashboard(context.Background(), storage.DashboardImportInput{OrganizationID: *organizationID, ActorUserID: *actor, MaxRows: cfg.Query.MaxRows, Bundle: bundle}, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Version        int    `json:"version"`
		OrganizationID string `json:"organization_id"`
		DashboardID    string `json:"dashboard_id"`
		Slug           string `json:"slug"`
	}{storage.DashboardVersion, imported.OrganizationID, imported.ID, imported.Slug})
}

func readDashboardBundle(reader io.Reader) (storage.DashboardExport, error) {
	const maximum = 1 << 20
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || len(body) > maximum {
		return storage.DashboardExport{}, errors.New("dashboard import must contain one JSON value no larger than 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var bundle storage.DashboardExport
	if err = decoder.Decode(&bundle); err != nil {
		return storage.DashboardExport{}, errors.New("dashboard import JSON is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return storage.DashboardExport{}, errors.New("dashboard import must contain one JSON value no larger than 1 MiB")
	}
	return bundle, nil
}

func migrateCommand(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow a non-root config owner for local development")
	rebuildOrganization := fs.String("rebuild-organization", "", "organization projection to rebuild from raw truth")
	approveRebuildOrganization := fs.String("approve-rebuild-organization", "", "exact organization identifier approving destructive projection replacement")
	applyRetention := fs.Bool("apply-retention", false, "apply configured retention and compaction after recovery")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("migrate accepts no positional arguments")
	}
	if *rebuildOrganization == "" && *approveRebuildOrganization != "" {
		return errors.New("approve-rebuild-organization requires rebuild-organization")
	}
	if *rebuildOrganization != "" && *approveRebuildOrganization != *rebuildOrganization {
		return errors.New("projection rebuild requires the exact organization identifier in approve-rebuild-organization")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, true)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	var report *storage.RebuildReport
	var retentionReport *storage.RetentionReport
	if *rebuildOrganization != "" {
		rebuilt, rebuildErr := store.RebuildOrganization(context.Background(), *rebuildOrganization, time.Now().UTC())
		if rebuildErr != nil {
			return rebuildErr
		}
		report = &rebuilt
	}
	if err = store.Recover(context.Background()); err != nil {
		return err
	}
	if *applyRetention {
		retained, retentionErr := store.ApplyRetention(context.Background(), retentionPolicy(cfg), time.Now().UTC())
		if retentionErr != nil {
			return retentionErr
		}
		retentionReport = &retained
	}
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	if *applyRetention {
		if _, err = identities.PruneEvidence(context.Background(), cfg.Retention.EvidenceDays, time.Now().UTC()); err != nil {
			return err
		}
	}
	if report != nil && retentionReport != nil {
		return json.NewEncoder(os.Stdout).Encode(struct {
			Rebuild   *storage.RebuildReport   `json:"rebuild"`
			Retention *storage.RetentionReport `json:"retention"`
		}{report, retentionReport})
	}
	if report != nil {
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if retentionReport != nil {
		return json.NewEncoder(os.Stdout).Encode(retentionReport)
	}
	fmt.Println("ok")
	return nil
}

func queryCommand(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root config ownership for local development")
	actor := fs.String("actor-user-id", "", "authorized user executing the local query")
	organizationID := fs.String("organization-id", "", "organization identifier")
	projectID := fs.String("project-id", "", "optional project identifier")
	environmentID := fs.String("environment-id", "", "optional environment identifier")
	serviceID := fs.String("service-id", "", "optional service identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("query accepts no positional arguments; provide query text on stdin")
	}
	text, err := io.ReadAll(io.LimitReader(os.Stdin, 16_385))
	if err != nil || len(text) > 16_384 {
		return errors.New("query input exceeds 16384 bytes")
	}
	ast, err := query.Parse(strings.TrimSpace(string(text)), 10_000)
	if err != nil {
		return err
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID, ProjectID: *projectID, EnvironmentID: *environmentID, ServiceID: *serviceID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionTelemetryQuery)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to query the requested scope")
	}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	sensitive, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionTelemetryReadSensitive)
	if err != nil {
		return err
	}
	result, err := store.Query(context.Background(), ast, query.Scope{
		OrganizationID: *organizationID, ProjectID: *projectID,
		EnvironmentID: *environmentID, ServiceID: *serviceID,
		Sensitive: sensitive.Allowed,
	}, query.Budget{MaxDuration: cfg.Query.MaxDuration, MaxRows: cfg.Query.MaxRows, MaxScannedBytes: cfg.Query.MaxScannedBytes, MaxMemoryBytes: cfg.Query.MaxMemoryBytes}, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func agentCommand(args []string) error {
	if len(args) > 0 && args[0] == "enroll" {
		return agentEnrollCommand(args[1:])
	}
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	path := fs.String("config", "/etc/gamertan-observatory/agent.json", "absolute agent configuration path")
	credentialPath := fs.String("credential-file", "", "absolute credential path overriding credential_file")
	systemdCredentials := fs.Bool("systemd-credentials", false, "read config and credential from CREDENTIALS_DIRECTORY")
	once := fs.Bool("once", false, "run one collect-and-deliver cycle")
	unsafeOwner := fs.Bool("development-allow-nonroot-config", false, "allow non-root config and credential ownership for local development")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("agent accepts no positional arguments")
	}
	policy := config.FilePolicy{RequireRoot: !*unsafeOwner}
	if *systemdCredentials {
		if *unsafeOwner {
			return errors.New("systemd-credentials and development-allow-nonroot-config are mutually exclusive")
		}
		var err error
		policy, err = config.SystemdCredentialPolicy()
		if err != nil {
			return err
		}
	}
	cfg, err := config.LoadAgent(*path, policy)
	if err != nil {
		return err
	}
	selectedCredentialPath := cfg.CredentialFile
	if *credentialPath != "" {
		selectedCredentialPath = *credentialPath
	}
	credential, err := config.LoadCredential(selectedCredentialPath, policy)
	if err != nil {
		return err
	}
	runner, err := obsagent.Open(cfg, credential, nil)
	if err != nil {
		return err
	}
	if *once {
		return runner.RunOnce(context.Background(), time.Now().UTC())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(cfg.FlushEvery)
	defer ticker.Stop()
	for {
		if err = runner.RunOnce(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("observatory agent cycle: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func agentEnrollCommand(args []string) error {
	fs := flag.NewFlagSet("agent enroll", flag.ContinueOnError)
	path := fs.String("config", "/etc/gamertan-observatory/agent.json", "absolute agent configuration path")
	enrollmentFile := fs.String("enrollment-file", "", "absolute private enrollment-token file")
	unsafeOwner := fs.Bool("development-allow-nonroot-config", false, "allow non-root config and enrollment ownership for local development")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("agent enroll accepts no positional arguments")
	}
	cfg, err := config.LoadAgent(*path, config.FilePolicy{RequireRoot: !*unsafeOwner})
	if err != nil {
		return err
	}
	token, err := config.LoadEnrollmentToken(*enrollmentFile, config.FilePolicy{RequireRoot: !*unsafeOwner})
	if err != nil {
		return err
	}
	result, err := agentclient.Enroll(context.Background(), cfg.ServerURL, token, nil)
	if err != nil {
		return err
	}
	if err = config.WriteCredential(cfg.CredentialFile, result.Credential); err != nil {
		if revokeErr := agentclient.RevokeSource(context.Background(), cfg.ServerURL, result.Credential, nil); revokeErr != nil {
			return fmt.Errorf("persist enrolled credential: %w; automatic source revocation also failed: %v", err, revokeErr)
		}
		return fmt.Errorf("persist enrolled credential: %w; enrolled source was revoked", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		SourceID string `json:"source_id"`
	}{result.SourceID})
}

type serverConfigFlags struct {
	path              *string
	allowNonRoot      *bool
	systemdCredential *bool
}

func addServerConfigFlags(fs *flag.FlagSet, developmentHelp string) serverConfigFlags {
	return serverConfigFlags{
		path:              fs.String("config", "/etc/gamertan-observatory/server.json", "absolute server configuration path"),
		allowNonRoot:      fs.Bool("development-allow-nonroot-config", false, developmentHelp),
		systemdCredential: fs.Bool("systemd-credential-config", false, "load the server configuration from CREDENTIALS_DIRECTORY"),
	}
}

func (flags serverConfigFlags) load() (config.Server, error) {
	if *flags.allowNonRoot && *flags.systemdCredential {
		return config.Server{}, errors.New("development non-root configuration and systemd credentials are mutually exclusive")
	}
	policy := config.FilePolicy{RequireRoot: !*flags.allowNonRoot}
	if *flags.systemdCredential {
		var err error
		policy, err = config.SystemdCredentialPolicy()
		if err != nil {
			return config.Server{}, err
		}
	}
	return config.LoadServer(*flags.path, policy)
}

func (flags serverConfigFlags) requireRootAuxiliaryFile() bool {
	return !*flags.allowNonRoot
}

func commandConfig(name string, args []string) (config.Server, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow a non-root config owner for local development")
	if err := fs.Parse(args); err != nil {
		return config.Server{}, err
	}
	if fs.NArg() != 0 {
		return config.Server{}, fmt.Errorf("%s accepts no positional arguments", name)
	}
	return configFlags.load()
}

func optionalPushDispatcher(notifier *webpush.Notifier) httpserver.PushDispatcher {
	if notifier == nil {
		return nil
	}
	return notifier
}

func serve(cfg config.Server) error {
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.RecoverRaw(context.Background()); err != nil {
		return err
	}
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	var pushNotifier *webpush.Notifier
	var pushPublicKey string
	if cfg.WebPush != nil {
		pushSender, senderErr := webpush.New(webpush.Options{PrivateKey: cfg.WebPush.PrivateKey, Subject: cfg.WebPush.Subject, Timeout: cfg.WebPush.Timeout})
		if senderErr != nil {
			return senderErr
		}
		pushNotifier, err = webpush.NewNotifier(store, identities.Access, pushSender, cfg.WebPush.QueueCapacity)
		if err != nil {
			return err
		}
		pushPublicKey = pushSender.PublicKey()
	}
	application, err := httpserver.New(store, identities, httpserver.Options{
		PublicOrigin: cfg.PublicURL, MaxBodyBytes: cfg.MaxBodyBytes, MaxConcurrentIngest: cfg.MaxConcurrentIngest,
		MaxQueryRows: cfg.Query.MaxRows, SessionLifetime: cfg.SessionLifetime,
		QueryBudget:   query.Budget{MaxDuration: cfg.Query.MaxDuration, MaxRows: cfg.Query.MaxRows, MaxScannedBytes: cfg.Query.MaxScannedBytes, MaxMemoryBytes: cfg.Query.MaxMemoryBytes},
		PushPublicKey: pushPublicKey, PushDispatcher: optionalPushDispatcher(pushNotifier),
	})
	if err != nil {
		return err
	}
	handler := application.Handler()
	server := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	backgroundJobs := make([]func(context.Context), 0, 4)
	backgroundJobs = append(backgroundJobs, func(background context.Context) {
		store.RunProjector(background, time.Second, func(error) {
			log.Print("observatory projection temporarily unavailable")
		})
	})
	if pushNotifier != nil {
		backgroundJobs = append(backgroundJobs, pushNotifier.Run)
	}
	backgroundJobs = append(backgroundJobs, func(background context.Context) {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		apply := func(now time.Time) {
			if _, retentionErr := store.ApplyRetention(background, retentionPolicy(cfg), now.UTC()); retentionErr != nil && !errors.Is(retentionErr, context.Canceled) {
				log.Print("observatory retention unavailable")
			}
			if _, retentionErr := identities.PruneEvidence(background, cfg.Retention.EvidenceDays, now.UTC()); retentionErr != nil && !errors.Is(retentionErr, context.Canceled) {
				log.Print("observatory identity retention unavailable")
			}
		}
		apply(time.Now())
		for {
			select {
			case <-background.Done():
				return
			case now := <-ticker.C:
				apply(now)
			}
		}
	})
	backgroundJobs = append(backgroundJobs, func(background context.Context) {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if _, evaluationErr := application.EvaluateAlerts(background); evaluationErr != nil && !errors.Is(evaluationErr, context.Canceled) {
				log.Print("observatory alert evaluation unavailable")
			}
			select {
			case <-background.Done():
				return
			case <-ticker.C:
			}
		}
	})
	return serveHTTPWithBackground(ctx, server, listener, backgroundJobs...)
}

func serveHTTPWithBackground(ctx context.Context, server *http.Server, listener net.Listener, jobs ...func(context.Context)) error {
	background, stopBackground := context.WithCancel(ctx)
	var backgroundJobs sync.WaitGroup
	defer func() {
		stopBackground()
		backgroundJobs.Wait()
	}()
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	for _, job := range jobs {
		backgroundJobs.Add(1)
		go func() {
			defer backgroundJobs.Done()
			job(background)
		}()
	}
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		log.Print("observatory server stopped")
		return nil
	}
}

func adminCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("admin command required: bootstrap, user create or reset-password, project create, environment create, service create, invitation create or accept, enrollment create, web-push generate-key, descriptors list, activate, reject, or retention set")
	}
	switch args[0] {
	case "bootstrap":
		return adminBootstrapCommand(args[1:])
	case "user":
		if len(args) < 2 {
			return errors.New("admin user command required: create or reset-password")
		}
		switch args[1] {
		case "create":
			return adminUserCreateCommand(args[2:])
		case "reset-password":
			return adminUserResetPasswordCommand(args[2:])
		default:
			return errors.New("admin user command required: create or reset-password")
		}
	case "project":
		if len(args) < 2 || args[1] != "create" {
			return errors.New("admin project command required: create")
		}
		return adminProjectCreateCommand(args[2:])
	case "environment":
		if len(args) < 2 || args[1] != "create" {
			return errors.New("admin environment command required: create")
		}
		return adminEnvironmentCreateCommand(args[2:])
	case "service":
		if len(args) < 2 || args[1] != "create" {
			return errors.New("admin service command required: create")
		}
		return adminServiceCreateCommand(args[2:])
	case "invitation":
		if len(args) < 2 {
			return errors.New("admin invitation command required: create or accept")
		}
		switch args[1] {
		case "create":
			return adminInvitationCreateCommand(args[2:])
		case "accept":
			return adminInvitationAcceptCommand(args[2:])
		default:
			return errors.New("admin invitation command required: create or accept")
		}
	case "enrollment":
		if len(args) < 2 || args[1] != "create" {
			return errors.New("admin enrollment command required: create")
		}
		return adminEnrollmentCreateCommand(args[2:])
	case "web-push":
		if len(args) < 2 || args[1] != "generate-key" {
			return errors.New("admin web-push command required: generate-key")
		}
		return adminWebPushGenerateKeyCommand(args[2:])
	case "descriptors":
		if len(args) < 2 {
			return errors.New("admin descriptors command required: list, activate, or reject")
		}
		switch args[1] {
		case "list":
			return adminDescriptorListCommand(args[2:])
		case "activate":
			return adminDescriptorActivateCommand(args[2:])
		case "reject":
			return adminDescriptorRejectCommand(args[2:])
		default:
			return errors.New("admin descriptors command required: list, activate, or reject")
		}
	case "retention":
		if len(args) < 2 || args[1] != "set" {
			return errors.New("admin retention command required: set")
		}
		return adminRetentionSetCommand(args[2:])
	default:
		return errors.New("admin command required: bootstrap, user create or reset-password, project create, environment create, service create, invitation create or accept, enrollment create, web-push generate-key, descriptors list, activate, reject, or retention set")
	}
}

func retentionPolicy(cfg config.Server) storage.RetentionPolicy {
	return storage.RetentionPolicy{
		RawLogsDays: cfg.Retention.RawLogsDays, RawTracesDays: cfg.Retention.RawTracesDays,
		RawMetricsDays: cfg.Retention.RawMetricsDays, ColdRawDays: cfg.Retention.ColdRawDays, MetricRollupsDays: cfg.Retention.MetricRollupsDays,
		DeleteColdRaw: cfg.Retention.DeleteColdRaw, EvidenceDays: cfg.Retention.EvidenceDays,
	}
}

func adminRetentionSetCommand(args []string) error {
	fs := flag.NewFlagSet("admin retention set", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization owner changing retention")
	organizationID := fs.String("organization-id", "", "organization identifier")
	rawLogs := fs.Int("raw-logs-days", 0, "raw log retention in days")
	rawTraces := fs.Int("raw-traces-days", 0, "raw trace retention in days")
	rawMetrics := fs.Int("raw-metrics-days", 0, "raw metric retention in days")
	coldRaw := fs.Int("cold-raw-days", 0, "cold forensic raw-segment retention in days")
	deleteColdRaw := fs.Bool("delete-cold-raw", false, "explicitly delete cold raw segments after their retention window")
	metricRollups := fs.Int("metric-rollups-days", 0, "five-minute metric rollup retention in days")
	evidence := fs.Int("evidence-days", 0, "deployment, incident, and audit evidence retention in days")
	approveExtension := fs.String("approve-extension", "", "exact organization identifier approving retention beyond server defaults")
	quotaBytes := fs.Int64("quota-bytes", 0, "positive storage quota required for an approved extension")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin retention set accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionOrganizationManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to change retention for the requested organization")
	}
	policy, err := store.SetOrganizationRetention(context.Background(), storage.SetRetentionInput{
		OrganizationID: *organizationID, ActorUserID: *actor, Defaults: retentionPolicy(cfg),
		Policy:              storage.RetentionPolicy{RawLogsDays: *rawLogs, RawTracesDays: *rawTraces, RawMetricsDays: *rawMetrics, ColdRawDays: *coldRaw, DeleteColdRaw: *deleteColdRaw, MetricRollupsDays: *metricRollups, EvidenceDays: *evidence},
		ApproveExtensionFor: *approveExtension, QuotaBytes: *quotaBytes,
	}, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(policy)
}

func adminWebPushGenerateKeyCommand(args []string) error {
	fs := flag.NewFlagSet("admin web-push generate-key", flag.ContinueOnError)
	output := fs.String("output-file", "", "new mode-0600 Web Push private-key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" {
		return errors.New("admin web-push generate-key requires --output-file and no positional arguments")
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate Web Push private key")
	}
	if err = config.WriteWebPushPrivateKey(*output, key.Bytes()); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		PrivateKeyFile string `json:"private_key_file"`
	}{*output})
}

func adminDescriptorActivateCommand(args []string) error {
	fs := flag.NewFlagSet("admin descriptors activate", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration and descriptor ownership for local development")
	actor := fs.String("actor-user-id", "", "organization member activating the reviewed descriptor")
	organizationID := fs.String("organization-id", "", "organization identifier")
	descriptorFile := fs.String("descriptor-file", "", "absolute private reviewed-descriptor JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin descriptors activate accepts no positional arguments")
	}
	reviewed, err := readReviewedDescriptor(*descriptorFile, configFlags.requireRootAuxiliaryFile())
	if err != nil {
		return err
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionSchemaManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to activate descriptors for the requested organization")
	}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	activation, err := store.ActivateDescriptor(context.Background(), *organizationID, reviewed, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(activation)
}

func adminDescriptorRejectCommand(args []string) error {
	fs := flag.NewFlagSet("admin descriptors reject", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization member rejecting the descriptor proposal")
	organizationID := fs.String("organization-id", "", "organization identifier")
	signalName := fs.String("signal", "", "proposal signal: logs, metrics, traces, or deployments")
	field := fs.String("field", "", "proposal field")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin descriptors reject accepts no positional arguments")
	}
	signal := model.Signal(*signalName)
	switch signal {
	case model.SignalLogs, model.SignalMetrics, model.SignalTraces, model.SignalDeployments:
	default:
		return errors.New("descriptor signal is invalid")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionSchemaManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to reject descriptors for the requested organization")
	}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	if err = store.RejectDescriptorProposal(context.Background(), *organizationID, signal, *field); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OrganizationID string       `json:"organization_id"`
		Signal         model.Signal `json:"signal"`
		Field          string       `json:"field"`
		Status         string       `json:"status"`
	}{*organizationID, signal, query.CanonicalField(*field), "rejected"})
}

func readReviewedDescriptor(path string, requireRoot bool) (schema.Descriptor, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return schema.Descriptor{}, errors.New("reviewed descriptor path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return schema.Descriptor{}, fmt.Errorf("inspect reviewed descriptor: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 2 || info.Size() > 64<<10 {
		return schema.Descriptor{}, errors.New("reviewed descriptor must be a private regular non-symlink file no larger than 64 KiB")
	}
	if requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return schema.Descriptor{}, errors.New("reviewed descriptor must be owned by root")
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return schema.Descriptor{}, fmt.Errorf("open reviewed descriptor: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var descriptor schema.Descriptor
	if err = decoder.Decode(&descriptor); err != nil {
		return schema.Descriptor{}, errors.New("reviewed descriptor JSON is invalid")
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return schema.Descriptor{}, errors.New("reviewed descriptor JSON must contain one value")
	}
	if err = descriptor.Validate(); err != nil {
		return schema.Descriptor{}, fmt.Errorf("reviewed descriptor: %w", err)
	}
	return descriptor, nil
}

func adminDescriptorListCommand(args []string) error {
	fs := flag.NewFlagSet("admin descriptors list", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization member reviewing descriptor proposals")
	organizationID := fs.String("organization-id", "", "organization identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin descriptors list accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionSchemaManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to review descriptors for the requested organization")
	}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	proposals, err := store.DescriptorProposals(context.Background(), *organizationID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(proposals)
}

func adminBootstrapCommand(args []string) error {
	fs := flag.NewFlagSet("admin bootstrap", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root config and secret ownership for local development")
	username := fs.String("username", "", "first operator username")
	email := fs.String("email", "", "first operator email address")
	displayName := fs.String("display-name", "", "first operator display name")
	passwordFile := fs.String("password-file", "", "absolute path to a private one-line password file")
	generatedPasswordFile := fs.String("generate-password-file", "", "create an exclusive private one-time password file at this absolute path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin bootstrap accepts no positional arguments")
	}
	if (*passwordFile == "") == (*generatedPasswordFile == "") {
		return errors.New("provide exactly one of --password-file or --generate-password-file")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	password := ""
	requirePasswordChange := *generatedPasswordFile != ""
	if requirePasswordChange {
		password, err = auth.GenerateTemporaryPassword(nil)
		if err == nil {
			err = identity.WriteSecret(*generatedPasswordFile, password)
		}
	} else {
		password, err = identity.ReadSecret(*passwordFile, configFlags.requireRootAuxiliaryFile())
	}
	if err != nil {
		return err
	}
	result, err := identities.Bootstrap(context.Background(), identity.BootstrapInput{Username: *username, Email: *email, DisplayName: *displayName, Password: password, RequirePasswordChange: requirePasswordChange})
	if err != nil {
		if requirePasswordChange {
			return errors.Join(err, identity.RemoveSecret(*generatedPasswordFile, configFlags.requireRootAuxiliaryFile()))
		}
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		UserID                 string `json:"user_id"`
		OrganizationID         string `json:"personal_organization_id"`
		PasswordChangeRequired bool   `json:"password_change_required"`
	}{result.User.ID, result.Organization.ID, result.User.PasswordChangeRequired})
}

func adminUserCreateCommand(args []string) error {
	fs := flag.NewFlagSet("admin user create", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root config and secret ownership for local development")
	username := fs.String("username", "", "new user's username")
	email := fs.String("email", "", "new user's email address")
	displayName := fs.String("display-name", "", "new user's display name")
	passwordFile := fs.String("password-file", "", "absolute path to a private one-line password file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin user create accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	password, err := identity.ReadSecret(*passwordFile, configFlags.requireRootAuxiliaryFile())
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	provisioned, err := identities.ProvisionUser(context.Background(), auth.CreateUser{Username: *username, Email: *email, DisplayName: *displayName, Password: password})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		UserID                 string `json:"user_id"`
		Email                  string `json:"email"`
		PersonalOrganizationID string `json:"personal_organization_id"`
	}{provisioned.User.ID, provisioned.User.Email, provisioned.Organization.ID})
}

func adminUserResetPasswordCommand(args []string) error {
	fs := flag.NewFlagSet("admin user reset-password", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root config and secret ownership for local development")
	identifier := fs.String("identifier", "", "existing username or email address")
	generatedPasswordFile := fs.String("generate-password-file", "", "create an exclusive private one-time password file at this absolute path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin user reset-password accepts no positional arguments")
	}
	if strings.TrimSpace(*identifier) == "" || *generatedPasswordFile == "" {
		return errors.New("admin user reset-password requires --identifier and --generate-password-file")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	password, err := auth.GenerateTemporaryPassword(nil)
	if err == nil {
		err = identity.WriteSecret(*generatedPasswordFile, password)
	}
	if err != nil {
		return err
	}
	removeCredential := func(requireRoot bool) error {
		return identity.RemoveSecret(*generatedPasswordFile, requireRoot)
	}
	persisted, err := identity.ReadSecret(*generatedPasswordFile, configFlags.requireRootAuxiliaryFile())
	if err != nil || persisted != password {
		return errors.Join(errors.New("admin user reset-password could not verify private credential delivery"), removeCredential(false))
	}
	user, err := identities.Auth.ResetPassword(context.Background(), auth.AdministrativePasswordReset{Identifier: *identifier, TemporaryPassword: password})
	if err != nil {
		return errors.Join(err, removeCredential(configFlags.requireRootAuxiliaryFile()))
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		UserID                 string `json:"user_id"`
		Username               string `json:"username"`
		PasswordChangeRequired bool   `json:"password_change_required"`
		SessionsRevoked        bool   `json:"sessions_revoked"`
	}{user.ID, user.Username, user.PasswordChangeRequired, true})
}

func adminProjectCreateCommand(args []string) error {
	fs := flag.NewFlagSet("admin project create", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization owner creating the project")
	organizationID := fs.String("organization-id", "", "organization identifier")
	slug := fs.String("slug", "", "project slug")
	name := fs.String("name", "", "project name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin project create accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	scope := access.Scope{OrganizationID: *organizationID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, scope, identity.PermissionOrganizationManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to create projects for the requested organization")
	}
	if err = identities.ValidateResourceScope(context.Background(), scope); err != nil {
		return err
	}
	project, err := identities.Organizations.CreateProject(context.Background(), organizations.CreateProject{OrganizationID: *organizationID, Slug: *slug, Name: *name})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		Slug           string `json:"slug"`
	}{project.OrganizationID, project.ID, project.Slug})
}

func adminEnvironmentCreateCommand(args []string) error {
	fs := flag.NewFlagSet("admin environment create", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization owner creating the environment")
	organizationID := fs.String("organization-id", "", "organization identifier")
	projectID := fs.String("project-id", "", "parent project identifier")
	slug := fs.String("slug", "", "environment slug")
	name := fs.String("name", "", "environment name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin environment create accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	organizationScope := access.Scope{OrganizationID: *organizationID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, organizationScope, identity.PermissionOrganizationManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to create environments for the requested organization")
	}
	if err = identities.ValidateResourceScope(context.Background(), access.Scope{OrganizationID: *organizationID, ProjectID: *projectID}); err != nil {
		return err
	}
	environment, err := identities.Organizations.CreateEnvironment(context.Background(), organizations.CreateEnvironment{OrganizationID: *organizationID, ProjectID: *projectID, Slug: *slug, Name: *name})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		EnvironmentID  string `json:"environment_id"`
		Slug           string `json:"slug"`
	}{environment.OrganizationID, environment.ProjectID, environment.ID, environment.Slug})
}

func adminServiceCreateCommand(args []string) error {
	fs := flag.NewFlagSet("admin service create", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization owner creating the application service")
	organizationID := fs.String("organization-id", "", "organization identifier")
	projectID := fs.String("project-id", "", "parent project identifier")
	environmentID := fs.String("environment-id", "", "parent environment identifier")
	slug := fs.String("slug", "", "application service slug")
	name := fs.String("name", "", "application service name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin service create accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	organizationScope := access.Scope{OrganizationID: *organizationID}
	parentScope := access.Scope{OrganizationID: *organizationID, ProjectID: *projectID, EnvironmentID: *environmentID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, organizationScope, identity.PermissionOrganizationManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to create application services for the requested organization")
	}
	if err = identities.ValidateResourceScope(context.Background(), parentScope); err != nil {
		return err
	}
	application, err := identities.Organizations.CreateApplicationService(context.Background(), organizations.CreateApplicationService{OrganizationID: *organizationID, ProjectID: *projectID, EnvironmentID: *environmentID, Slug: *slug, Name: *name})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		EnvironmentID  string `json:"environment_id"`
		ServiceID      string `json:"service_id"`
		Slug           string `json:"slug"`
	}{application.OrganizationID, application.ProjectID, application.EnvironmentID, application.ID, application.Slug})
}

func adminInvitationCreateCommand(args []string) error {
	fs := flag.NewFlagSet("admin invitation create", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration and token ownership for local development")
	actor := fs.String("actor-user-id", "", "organization owner creating the invitation")
	organizationID := fs.String("organization-id", "", "organization identifier")
	email := fs.String("email", "", "invited user's exact email address")
	lifetime := fs.Duration("lifetime", 15*time.Minute, "single-use invitation lifetime")
	output := fs.String("output-file", "", "new mode-0600 invitation-token file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" {
		return errors.New("admin invitation create requires --output-file and no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionOrganizationManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to create invitations for the requested organization")
	}
	raw, invitation, err := identities.Organizations.Invite(context.Background(), *organizationID, *email, *actor, *lifetime)
	if err != nil {
		return err
	}
	if err = identity.WriteSecret(*output, raw); err != nil {
		if cancelErr := identities.CancelUnusedInvitation(context.Background(), invitation.Digest); cancelErr != nil {
			return fmt.Errorf("persist invitation token: %w; automatic invitation cancellation also failed: %v", err, cancelErr)
		}
		return fmt.Errorf("persist invitation token: %w; invitation was cancelled", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OrganizationID string    `json:"organization_id"`
		Email          string    `json:"email"`
		ExpiresAt      time.Time `json:"expires_at"`
		InvitationFile string    `json:"invitation_file"`
	}{invitation.OrganizationID, invitation.Email, invitation.ExpiresAt, *output})
}

func adminInvitationAcceptCommand(args []string) error {
	fs := flag.NewFlagSet("admin invitation accept", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration and token ownership for local development")
	userID := fs.String("user-id", "", "invited user's identifier")
	invitationFile := fs.String("invitation-file", "", "absolute private invitation-token file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin invitation accept accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	raw, err := identity.ReadSecret(*invitationFile, configFlags.requireRootAuxiliaryFile())
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	if err = identities.Organizations.AcceptInvitation(context.Background(), raw, *userID); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		UserID string `json:"user_id"`
		Status string `json:"status"`
	}{*userID, "accepted"})
}

func adminEnrollmentCreateCommand(args []string) error {
	fs := flag.NewFlagSet("admin enrollment create", flag.ContinueOnError)
	configFlags := addServerConfigFlags(fs, "allow non-root configuration ownership for local development")
	actor := fs.String("actor-user-id", "", "organization member creating the enrollment")
	sourceID := fs.String("source-id", "", "new source identifier")
	organizationID := fs.String("organization-id", "", "organization identifier")
	projectID := fs.String("project-id", "", "project identifier")
	environmentID := fs.String("environment-id", "", "environment identifier")
	serviceID := fs.String("service-id", "", "service identifier")
	lifetime := fs.Duration("lifetime", 15*time.Minute, "single-use enrollment lifetime")
	output := fs.String("output-file", "", "new mode-0600 enrollment-token file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin enrollment create accepts no positional arguments")
	}
	cfg, err := configFlags.load()
	if err != nil {
		return err
	}
	processLock, err := storage.AcquireProcessLock(cfg.DataDir, false)
	if err != nil {
		return err
	}
	defer processLock.Close()
	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	identities, err := identity.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer identities.Close()
	requested := access.Scope{OrganizationID: *organizationID, ProjectID: *projectID, EnvironmentID: *environmentID, ServiceID: *serviceID}
	decision, err := identities.Access.Authorize(context.Background(), *actor, requested, identity.PermissionSourcesManage)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.New("actor is not authorized to manage sources in the requested scope")
	}
	if err = identities.ValidateResourceScope(context.Background(), requested); err != nil {
		return err
	}
	scope := model.Scope{OrganizationID: *organizationID, ProjectID: *projectID, EnvironmentID: *environmentID, ServiceID: *serviceID}
	now := time.Now().UTC()
	token, enrollment, err := store.CreateEnrollment(context.Background(), *sourceID, scope, *actor, *lifetime, now)
	if err != nil {
		return err
	}
	if err = config.WriteEnrollmentToken(*output, token); err != nil {
		if cancelErr := store.CancelEnrollment(context.Background(), token); cancelErr != nil {
			return fmt.Errorf("persist enrollment token: %w; automatic cancellation also failed: %v", err, cancelErr)
		}
		return fmt.Errorf("persist enrollment token: %w; enrollment was cancelled", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		SourceID  string    `json:"source_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}{enrollment.SourceID, enrollment.ExpiresAt})
}
