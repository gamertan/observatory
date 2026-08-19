// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/schema"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/access"
	"gamertan.com/web/auth"
)

func TestNoCommandRequiresAnExplicitTendCandidateAddress(t *testing.T) {
	t.Setenv("OBSERVATORY_TEND_CANDIDATE_LISTEN", "")
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "command required") {
		t.Fatalf("run without command err=%v", err)
	}
}

func TestTendCandidateHandlerIsStatelessAndBounded(t *testing.T) {
	handler := tendCandidateHandler()
	for _, test := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/", "Gamertan Observatory candidate\n"},
		{http.MethodHead, "/", ""},
		{http.MethodGet, "/healthz", "ok\n"},
		{http.MethodHead, "/healthz", ""},
		{http.MethodGet, "/readyz", "ready\n"},
		{http.MethodHead, "/readyz", ""},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, "http://observatory.example"+test.path, nil))
		response := recorder.Result()
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != test.body {
			t.Fatalf("%s %s status=%d body=%q err=%v", test.method, test.path, response.StatusCode, body, err)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s %s security headers=%v", test.method, test.path, response.Header)
		}
	}
	for _, test := range []struct {
		method, path string
	}{
		{http.MethodPost, "/"},
		{http.MethodGet, "/api/v1/ingest/native"},
		{http.MethodGet, "/app/"},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, "http://observatory.example"+test.path, nil))
		if recorder.Code == http.StatusOK {
			t.Fatalf("candidate exposed %s %s", test.method, test.path)
		}
	}
}

func TestTendCandidateAddressRejectsNonLoopbackAndMalformedValues(t *testing.T) {
	for _, value := range []string{"", "localhost:18094", "0.0.0.0:18094", "192.0.2.1:18094", "127.0.0.1:0", "127.0.0.1", "127.0.0.1:70000"} {
		if err := serveTendCandidate(value); err == nil || !strings.Contains(err.Error(), "loopback IP address") {
			t.Fatalf("unsafe candidate address %q err=%v", value, err)
		}
	}
}

func TestTendCandidateProcessIsReadOnly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("loopback sockets are prohibited by this test sandbox")
		}
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	workingDirectory := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTendCandidateProcessHelper$")
	command.Dir = workingDirectory
	command.Env = append(os.Environ(), "OBSERVATORY_TEND_CANDIDATE_HELPER=1", "OBSERVATORY_TEND_CANDIDATE_LISTEN="+address)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 250 * time.Millisecond}
	ready := false
	for ctx.Err() == nil {
		response, requestErr := client.Get("http://" + address + "/readyz")
		if requestErr == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == "ready\n" {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("candidate did not become ready: %s", output.String())
	}
	if err = command.Process.Signal(os.Interrupt); err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	if err = command.Wait(); err != nil {
		t.Fatalf("candidate exit err=%v output=%s", err, output.String())
	}
	entries, err := os.ReadDir(workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("candidate wrote files: %v", entries)
	}
}

func TestTendCandidateProcessHelper(t *testing.T) {
	if os.Getenv("OBSERVATORY_TEND_CANDIDATE_HELPER") != "1" {
		return
	}
	if err := run(nil); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPServerAnswersReadinessWhileBackgroundMaintenanceIsBlocked(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("loopback sockets are prohibited by this test sandbox")
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	maintenanceStarted := make(chan struct{})
	maintenanceStopped := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" {
			http.NotFound(writer, request)
			return
		}
		_, _ = io.WriteString(writer, "ready\n")
	})}
	result := make(chan error, 1)
	go func() {
		result <- serveHTTPWithBackground(ctx, server, listener, func(background context.Context) {
			close(maintenanceStarted)
			<-background.Done()
			close(maintenanceStopped)
		})
	}()
	select {
	case <-maintenanceStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("background maintenance did not start")
	}
	client := &http.Client{Timeout: 250 * time.Millisecond}
	response, err := client.Get("http://" + listener.Addr().String() + "/readyz")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "ready\n" {
		cancel()
		t.Fatalf("readiness status=%d body=%q err=%v", response.StatusCode, body, readErr)
	}
	cancel()
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
	select {
	case <-maintenanceStopped:
	default:
		t.Fatal("server returned before background maintenance stopped")
	}
}

func TestCommandConfigSupportsConfinedSystemdCredentials(t *testing.T) {
	root := t.TempDir()
	credentialDirectory := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentialDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	path := writeTestServerConfig(t, credentialDirectory, data)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDirectory)
	cfg, err := commandConfig("server", []string{"--config", path, "--systemd-credential-config"})
	if err != nil || cfg.DataDir != data {
		t.Fatalf("config=%+v err=%v", cfg, err)
	}
	if err = os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if cfg, err = commandConfig("server", []string{"--config", path, "--systemd-credential-config"}); err != nil || cfg.DataDir != data {
		t.Fatalf("systemd mode-0440 config=%+v err=%v", cfg, err)
	}
	if _, err = commandConfig("server", []string{"--config", path, "--systemd-credential-config", "--development-allow-nonroot-config"}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("conflicting config policy err=%v", err)
	}
	out := filepath.Join(root, "outside.json")
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err = os.WriteFile(out, body, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err = commandConfig("server", []string{"--config", out, "--systemd-credential-config"}); err == nil || !strings.Contains(err.Error(), "direct child") {
		t.Fatalf("outside credential err=%v", err)
	}
}

func TestOptionalPushDispatcherDoesNotBoxANilNotifier(t *testing.T) {
	if dispatcher := optionalPushDispatcher(nil); dispatcher != nil {
		t.Fatalf("nil notifier became non-nil dispatcher: %#v", dispatcher)
	}
}

func TestAdminWebPushKeyGenerationIsPrivateAndExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-push.json")
	if err := adminWebPushGenerateKeyCommand([]string{"--output-file", path}); err != nil {
		t.Fatal(err)
	}
	key, err := config.LoadWebPushPrivateKey(path, config.FilePolicy{})
	if err != nil || len(key) != 32 {
		t.Fatalf("key length=%d err=%v", len(key), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info, err)
	}
	if err = adminWebPushGenerateKeyCommand([]string{"--output-file", path}); err == nil {
		t.Fatal("key generation overwrote an existing secret")
	}
}

func TestAdminBootstrapUsesSecretFileAndIsSingleUse(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	configPath := filepath.Join(root, "server.json")
	passwordPath := filepath.Join(root, "password")
	configuration := fmt.Sprintf(`{"schema":1,"listen":"127.0.0.1:9010","public_url":"https://observatory.example","data_dir":%q,"max_body_bytes":1048576,"session_lifetime":"12h","query":{"max_duration":"2s","max_rows":1000,"max_scanned_bytes":10485760,"max_memory_bytes":8388608},"retention":{"raw_logs_days":30,"raw_traces_days":30,"raw_metrics_days":14,"cold_raw_days":400,"metric_rollups_days":400,"evidence_days":400}}`, data)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	const password = "correct horse battery staple"
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"admin", "bootstrap", "--config", configPath, "--username", "operator", "--email", "operator@example.test", "--display-name", "First Operator", "--password-file", passwordPath, "--development-allow-nonroot-config"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	if err := run(args); !errors.Is(err, identity.ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap err=%v", err)
	}
	entries, err := os.ReadDir(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == ".bootstrap.lock" {
			continue
		}
		body, readErr := os.ReadFile(filepath.Join(data, entry.Name()))
		if readErr == nil && strings.Contains(string(body), password) {
			t.Fatalf("password leaked into %s", entry.Name())
		}
	}
}

func TestAdminBootstrapGeneratesExclusiveOneTimeCredential(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, root, data)
	passwordPath := filepath.Join(root, "generated-bootstrap-password")
	args := []string{"--config", configPath, "--username", "speelman", "--email", "crspeelman@gmail.com", "--display-name", "Cole Speelman", "--generate-password-file", passwordPath, "--development-allow-nonroot-config"}
	var result struct {
		UserID                 string `json:"user_id"`
		OrganizationID         string `json:"personal_organization_id"`
		PasswordChangeRequired bool   `json:"password_change_required"`
	}
	captureCommandJSON(t, adminBootstrapCommand, args, &result)
	if result.UserID == "" || result.OrganizationID == "" || !result.PasswordChangeRequired {
		t.Fatalf("result=%+v", result)
	}
	info, err := os.Lstat(passwordPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("password file info=%v err=%v", info, err)
	}
	password, err := identity.ReadSecret(passwordPath, false)
	if err != nil || len(password) != 43 || strings.ContainsAny(password, "\r\n") {
		t.Fatalf("generated credential length=%d err=%v", len(password), err)
	}
	identities, err := identity.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	_, principal, err := identities.Auth.Authenticate(t.Context(), "speelman", password, time.Hour)
	if err != nil || principal.User.Email != "crspeelman@gmail.com" || principal.User.DisplayName != "Cole Speelman" || !principal.User.PasswordChangeRequired {
		identities.Close()
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
	if err = identities.Close(); err != nil {
		t.Fatal(err)
	}
	secondPath := filepath.Join(root, "second-bootstrap-password")
	second := append([]string{}, args...)
	second[9] = secondPath
	if err = adminBootstrapCommand(second); !errors.Is(err, identity.ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap err=%v", err)
	}
	if _, err = os.Lstat(secondPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed bootstrap retained generated credential: %v", err)
	}
	for _, invalid := range [][]string{
		{"--config", configPath, "--username", "x", "--email", "x@example.test", "--display-name", "X", "--development-allow-nonroot-config"},
		{"--config", configPath, "--username", "x", "--email", "x@example.test", "--display-name", "X", "--password-file", passwordPath, "--generate-password-file", secondPath, "--development-allow-nonroot-config"},
	} {
		if err = adminBootstrapCommand(invalid); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("invalid bootstrap flags err=%v", err)
		}
	}
}

func TestAdminBootstrapSupportsConfinedSystemdCredentials(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, credentials, data)
	if err := os.Chmod(configPath, 0o440); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(root, "generated-password")
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	args := []string{"--config", configPath, "--username", "operator", "--email", "operator@example.test", "--display-name", "First Operator", "--generate-password-file", passwordPath, "--systemd-credential-config"}
	var result struct {
		PasswordChangeRequired bool `json:"password_change_required"`
	}
	captureCommandJSON(t, adminBootstrapCommand, args, &result)
	if !result.PasswordChangeRequired {
		t.Fatalf("result=%+v", result)
	}
	if _, err := identity.ReadSecret(passwordPath, false); err != nil {
		t.Fatal(err)
	}
	conflicting := append(append([]string{}, args...), "--development-allow-nonroot-config")
	if err := adminBootstrapCommand(conflicting); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("conflicting config policies err=%v", err)
	}
}

func TestAdminUserResetPasswordGeneratesPrivateCredentialAndRevokesSessions(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, root, data)
	bootstrapPath := filepath.Join(root, "bootstrap-password")
	common := []string{"--config", configPath, "--development-allow-nonroot-config"}
	var bootstrap struct {
		UserID string `json:"user_id"`
	}
	captureCommandJSON(t, adminBootstrapCommand, append(append([]string{}, common...), "--username", "speelman", "--email", "operator@example.test", "--display-name", "Operator", "--generate-password-file", bootstrapPath), &bootstrap)
	bootstrapPassword, err := identity.ReadSecret(bootstrapPath, false)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := identities.Auth.Authenticate(t.Context(), "speelman", bootstrapPassword, time.Hour)
	if err != nil {
		identities.Close()
		t.Fatal(err)
	}
	if err = identities.Close(); err != nil {
		t.Fatal(err)
	}
	recoveryPath := filepath.Join(root, "recovery-password")
	var result struct {
		UserID                 string `json:"user_id"`
		Username               string `json:"username"`
		PasswordChangeRequired bool   `json:"password_change_required"`
		SessionsRevoked        bool   `json:"sessions_revoked"`
	}
	body := captureCommandJSON(t, adminUserResetPasswordCommand, append(append([]string{}, common...), "--identifier", "operator@example.test", "--generate-password-file", recoveryPath), &result)
	if result.UserID != bootstrap.UserID || result.Username != "speelman" || !result.PasswordChangeRequired || !result.SessionsRevoked {
		t.Fatalf("result=%+v", result)
	}
	recoveryPassword, err := identity.ReadSecret(recoveryPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), recoveryPassword) || strings.Contains(string(body), recoveryPath) {
		t.Fatal("command output disclosed the recovery credential or its path")
	}
	identities, err = identity.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	if _, err = identities.Auth.Session(t.Context(), token); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("old session survived recovery: %v", err)
	}
	if _, _, err = identities.Auth.Authenticate(t.Context(), "speelman", bootstrapPassword, time.Hour); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("bootstrap credential survived recovery: %v", err)
	}
	_, principal, err := identities.Auth.Authenticate(t.Context(), "speelman", recoveryPassword, time.Hour)
	if err != nil || !principal.User.PasswordChangeRequired {
		t.Fatalf("recovery principal=%+v err=%v", principal, err)
	}
	if err = adminUserResetPasswordCommand(append(append([]string{}, common...), "--identifier", "speelman", "--generate-password-file", recoveryPath)); err == nil {
		t.Fatal("recovery credential file was overwritten")
	}
	missingPath := filepath.Join(root, "missing-user-password")
	if err = adminUserResetPasswordCommand(append(append([]string{}, common...), "--identifier", "missing-user", "--generate-password-file", missingPath)); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("missing user err=%v", err)
	}
	if _, err = os.Lstat(missingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery retained credential: %v", err)
	}
}

func TestAdminHierarchyAndEnrollmentSupportConfinedSystemdCredentials(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, credentials, data)
	if err := os.Chmod(configPath, 0o440); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	common := []string{"--config", configPath, "--systemd-credential-config"}
	passwordPath := filepath.Join(root, "generated-password")
	var owner struct {
		UserID         string `json:"user_id"`
		OrganizationID string `json:"personal_organization_id"`
	}
	bootstrap := append(append([]string{}, common...), "--username", "operator", "--email", "operator@example.test", "--display-name", "Operator", "--generate-password-file", passwordPath)
	captureCommandJSON(t, adminBootstrapCommand, bootstrap, &owner)

	var project struct {
		ProjectID string `json:"project_id"`
	}
	projectArgs := append(append([]string{}, common...), "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--slug", "observatory", "--name", "Gamertan Observatory")
	captureCommandJSON(t, adminProjectCreateCommand, projectArgs, &project)
	var environment struct {
		EnvironmentID string `json:"environment_id"`
	}
	environmentArgs := append(append([]string{}, common...), "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--project-id", project.ProjectID, "--slug", "production", "--name", "Production")
	captureCommandJSON(t, adminEnvironmentCreateCommand, environmentArgs, &environment)
	var service struct {
		ServiceID string `json:"service_id"`
	}
	serviceArgs := append(append([]string{}, common...), "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--project-id", project.ProjectID, "--environment-id", environment.EnvironmentID, "--slug", "observatory", "--name", "Observatory")
	captureCommandJSON(t, adminServiceCreateCommand, serviceArgs, &service)

	enrollmentFile := filepath.Join(root, "enrollment-token")
	var enrollment struct {
		SourceID string `json:"source_id"`
	}
	enrollmentArgs := append(append([]string{}, common...), "--actor-user-id", owner.UserID, "--source-id", "observatory-production", "--organization-id", owner.OrganizationID, "--project-id", project.ProjectID, "--environment-id", environment.EnvironmentID, "--service-id", service.ServiceID, "--output-file", enrollmentFile)
	captureCommandJSON(t, adminEnrollmentCreateCommand, enrollmentArgs, &enrollment)
	if project.ProjectID == "" || environment.EnvironmentID == "" || service.ServiceID == "" || enrollment.SourceID != "observatory-production" {
		t.Fatalf("project=%+v environment=%+v service=%+v enrollment=%+v", project, environment, service, enrollment)
	}
	if _, err := config.LoadEnrollmentToken(enrollmentFile, config.FilePolicy{}); err != nil {
		t.Fatal(err)
	}
	var proposals []schema.Proposal
	descriptors := append(append([]string{}, common...), "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID)
	captureCommandJSON(t, adminDescriptorListCommand, descriptors, &proposals)
}

func TestAdminResourceCommandsCreateAnAuthorizedEnrollableHierarchy(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, root, data)
	ownerPassword := filepath.Join(root, "owner-password")
	memberPassword := filepath.Join(root, "member-password")
	if err := os.WriteFile(ownerPassword, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memberPassword, []byte("another correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--config", configPath, "--development-allow-nonroot-config"}
	var owner struct {
		UserID         string `json:"user_id"`
		OrganizationID string `json:"personal_organization_id"`
	}
	captureCommandJSON(t, adminBootstrapCommand, append(append([]string{}, common...), "--username", "operator", "--email", "operator@example.test", "--display-name", "First Operator", "--password-file", ownerPassword), &owner)

	var project struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		Slug           string `json:"slug"`
	}
	projectArgs := append([]string{"admin", "project", "create"}, common...)
	projectArgs = append(projectArgs, "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--slug", "gamertan", "--name", "Gamertan")
	captureCommandJSON(t, run, projectArgs, &project)
	if project.OrganizationID != owner.OrganizationID || project.ProjectID == "" || project.Slug != "gamertan" {
		t.Fatalf("project=%+v", project)
	}

	var environment struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		EnvironmentID  string `json:"environment_id"`
		Slug           string `json:"slug"`
	}
	environmentArgs := append([]string{"admin", "environment", "create"}, common...)
	environmentArgs = append(environmentArgs, "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--project-id", project.ProjectID, "--slug", "production", "--name", "Production")
	captureCommandJSON(t, run, environmentArgs, &environment)
	if environment.ProjectID != project.ProjectID || environment.EnvironmentID == "" || environment.Slug != "production" {
		t.Fatalf("environment=%+v", environment)
	}

	var application struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		EnvironmentID  string `json:"environment_id"`
		ServiceID      string `json:"service_id"`
		Slug           string `json:"slug"`
	}
	serviceArgs := append([]string{"admin", "service", "create"}, common...)
	serviceArgs = append(serviceArgs, "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--project-id", project.ProjectID, "--environment-id", environment.EnvironmentID, "--slug", "observatory", "--name", "Gamertan Observatory")
	captureCommandJSON(t, run, serviceArgs, &application)
	if application.EnvironmentID != environment.EnvironmentID || application.ServiceID == "" || application.Slug != "observatory" {
		t.Fatalf("application=%+v", application)
	}

	identities, err := identity.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = identities.ValidateResourceScope(context.Background(), access.Scope{OrganizationID: owner.OrganizationID, ProjectID: project.ProjectID, EnvironmentID: environment.EnvironmentID, ServiceID: application.ServiceID}); err != nil {
		identities.Close()
		t.Fatal(err)
	}
	if err = identities.Close(); err != nil {
		t.Fatal(err)
	}

	var member struct {
		UserID string `json:"user_id"`
	}
	captureCommandJSON(t, adminUserCreateCommand, append(append([]string{}, common...), "--username", "member", "--email", "member@example.test", "--display-name", "Member", "--password-file", memberPassword), &member)
	unauthorized := append(append([]string{}, common...), "--actor-user-id", member.UserID, "--organization-id", owner.OrganizationID, "--slug", "forbidden", "--name", "Forbidden")
	if err = adminProjectCreateCommand(unauthorized); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized project err=%v", err)
	}
	wrongParent := append(append([]string{}, common...), "--actor-user-id", owner.UserID, "--organization-id", owner.OrganizationID, "--project-id", member.UserID, "--slug", "invalid", "--name", "Invalid")
	if err = adminEnvironmentCreateCommand(wrongParent); !errors.Is(err, identity.ErrResourceNotFound) {
		t.Fatalf("wrong parent err=%v", err)
	}
}

func captureCommandJSON(t *testing.T, command func([]string) error, args []string, target any) []byte {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	commandErr := command(args)
	closeErr := writer.Close()
	os.Stdout = original
	body, readErr := io.ReadAll(reader)
	reader.Close()
	if commandErr != nil {
		t.Fatal(commandErr)
	}
	if closeErr != nil || readErr != nil {
		t.Fatalf("capture close=%v read=%v", closeErr, readErr)
	}
	if err = json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode command output: %v", err)
	}
	return body
}

func TestAdminUserAndInvitationCommandsProvisionPrivateAndSharedAccess(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, root, data)
	ownerPassword := filepath.Join(root, "owner-password")
	memberPassword := filepath.Join(root, "member-password")
	otherPassword := filepath.Join(root, "other-password")
	invitationPath := filepath.Join(root, "invitation")
	if err := os.WriteFile(ownerPassword, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memberPassword, []byte("another correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPassword, []byte("a third correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--config", configPath, "--development-allow-nonroot-config"}
	if err := adminBootstrapCommand(append(append([]string{}, common...), "--username", "operator", "--email", "operator@example.test", "--display-name", "First Operator", "--password-file", ownerPassword)); err != nil {
		t.Fatal(err)
	}
	if err := adminUserCreateCommand(append(append([]string{}, common...), "--username", "responder", "--email", "responder@example.test", "--display-name", "Incident Responder", "--password-file", memberPassword)); err != nil {
		t.Fatal(err)
	}
	if err := adminUserCreateCommand(append(append([]string{}, common...), "--username", "other-user", "--email", "other@example.test", "--display-name", "Other User", "--password-file", otherPassword)); err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	_, owner, err := identities.Auth.Authenticate(t.Context(), "operator", "correct horse battery staple", time.Hour)
	if err != nil {
		identities.Close()
		t.Fatal(err)
	}
	_, member, err := identities.Auth.Authenticate(t.Context(), "responder", "another correct horse battery staple", time.Hour)
	if err != nil {
		identities.Close()
		t.Fatal(err)
	}
	_, other, err := identities.Auth.Authenticate(t.Context(), "other-user", "a third correct horse battery staple", time.Hour)
	if err != nil {
		identities.Close()
		t.Fatal(err)
	}
	ownerOrganizations, err := identities.OrganizationsForUser(t.Context(), owner.User.ID)
	if err != nil || len(ownerOrganizations) != 1 || !ownerOrganizations[0].Personal {
		identities.Close()
		t.Fatalf("owner organizations=%+v err=%v", ownerOrganizations, err)
	}
	memberOrganizations, err := identities.OrganizationsForUser(t.Context(), member.User.ID)
	if err != nil || len(memberOrganizations) != 1 || !memberOrganizations[0].Personal {
		identities.Close()
		t.Fatalf("member organizations=%+v err=%v", memberOrganizations, err)
	}
	if err = identities.Close(); err != nil {
		t.Fatal(err)
	}
	createArgs := append(append([]string{}, common...), "--actor-user-id", owner.User.ID, "--organization-id", ownerOrganizations[0].ID, "--email", member.User.Email, "--output-file", invitationPath)
	if err = adminInvitationCreateCommand(createArgs); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(invitationPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("invitation file=%v err=%v", info, err)
	}
	acceptArgs := append(append([]string{}, common...), "--user-id", member.User.ID, "--invitation-file", invitationPath)
	wrongUserArgs := append(append([]string{}, common...), "--user-id", other.User.ID, "--invitation-file", invitationPath)
	if err = adminInvitationAcceptCommand(wrongUserArgs); err == nil {
		t.Fatal("invitation was accepted by a user with a different email")
	}
	if err = adminInvitationAcceptCommand(acceptArgs); err != nil {
		t.Fatal(err)
	}
	if err = adminInvitationAcceptCommand(acceptArgs); err == nil {
		t.Fatal("single-use invitation was accepted twice")
	}
	identities, err = identity.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	memberOrganizations, err = identities.OrganizationsForUser(t.Context(), member.User.ID)
	if err != nil || len(memberOrganizations) != 2 {
		t.Fatalf("member organizations=%+v err=%v", memberOrganizations, err)
	}
	unauthorized := append(append([]string{}, common...), "--actor-user-id", member.User.ID, "--organization-id", ownerOrganizations[0].ID, "--email", "other@example.test", "--output-file", filepath.Join(root, "unauthorized-invitation"))
	if err = adminInvitationCreateCommand(unauthorized); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized invitation err=%v", err)
	}
}

func TestMigrateProjectionRebuildRequiresExactApproval(t *testing.T) {
	if err := migrateCommand([]string{"--rebuild-organization", "organization-a"}); err == nil || !strings.Contains(err.Error(), "exact organization identifier") {
		t.Fatalf("missing approval err=%v", err)
	}
	if err := migrateCommand([]string{"--approve-rebuild-organization", "organization-a"}); err == nil || !strings.Contains(err.Error(), "requires rebuild-organization") {
		t.Fatalf("orphan approval err=%v", err)
	}
	if err := migrateCommand([]string{"--rebuild-organization", "organization-a", "--approve-rebuild-organization", "organization-b"}); err == nil || !strings.Contains(err.Error(), "exact organization identifier") {
		t.Fatalf("mismatched approval err=%v", err)
	}
}

func TestDashboardImportJSONIsStrictBoundedAndExplicitlyApproved(t *testing.T) {
	valid := `{"version":1,"dashboard":{"slug":"operations","name":"Operations","description":"Portable view.","panels":[{"id":"panel-old","position":0,"title":"Requests","visualization":"table","saved_query_id":"query-old"}]},"saved_queries":[{"id":"query-old","name":"Requests","description":"Recent requests.","query":"logs | limit 10","scope":{}}]}`
	bundle, err := readDashboardBundle(strings.NewReader(valid))
	if err != nil || bundle.Version != storage.DashboardVersion || bundle.Dashboard.Slug != "operations" {
		t.Fatalf("bundle=%+v err=%v", bundle, err)
	}
	for name, body := range map[string]string{
		"unknown":  strings.Replace(valid, `"version":1`, `"version":1,"secret":"no"`, 1),
		"trailing": valid + `{}`,
		"oversize": valid + strings.Repeat(" ", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readDashboardBundle(strings.NewReader(body)); err == nil {
				t.Fatal("unsafe dashboard bundle was accepted")
			}
		})
	}
	if err = importCommand([]string{"--organization-id", "organization-a"}); err == nil || !strings.Contains(err.Error(), "exact organization identifier") {
		t.Fatalf("missing approval err=%v", err)
	}
}

func TestOfflineMigrationRefusesLiveDataDirectory(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	configPath := writeTestServerConfig(t, root, data)
	lock, err := storage.AcquireProcessLock(data, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	err = migrateCommand([]string{"--config", configPath, "--development-allow-nonroot-config"})
	if err == nil || !strings.Contains(err.Error(), "active in another process") {
		t.Fatalf("migration overlapped live lock: %v", err)
	}
}

func writeTestServerConfig(t *testing.T, root, data string) string {
	t.Helper()
	path := filepath.Join(root, "server.json")
	body := fmt.Sprintf(`{"schema":1,"listen":"127.0.0.1:9010","public_url":"https://observatory.example","data_dir":%q,"max_body_bytes":1048576,"session_lifetime":"12h","query":{"max_duration":"2s","max_rows":1000,"max_scanned_bytes":10485760,"max_memory_bytes":8388608},"retention":{"raw_logs_days":30,"raw_traces_days":30,"raw_metrics_days":14,"cold_raw_days":400,"metric_rollups_days":400,"evidence_days":400}}`, data)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReviewedDescriptorFileIsStrictPrivateAndNonSymlink(t *testing.T) {
	descriptor := schema.Descriptor{
		Version: schema.DescriptorVersion, Signal: model.SignalMetrics, Field: "workshop.queue_depth",
		Type: schema.TypeInteger, Meaning: "Reviewed queue depth for one service.",
		Sensitivity: schema.SensitivityInternal, Cardinality: schema.CardinalityLow,
		Index: schema.IndexRange, Retention: schema.RetentionRaw, ProjectionVersion: 1,
	}
	body, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "descriptor.json")
	if err = os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readReviewedDescriptor(path, false)
	if err != nil || got != descriptor {
		t.Fatalf("descriptor=%+v err=%v", got, err)
	}
	if err = os.WriteFile(path, []byte(`{"version":1,"signal":"metrics","field":"workshop.queue_depth","type":"integer","meaning":"Reviewed queue depth for one service.","sensitivity":"internal","cardinality":"low","index":"range","retention":"raw","projection_version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = readReviewedDescriptor(path, false); err == nil {
		t.Fatal("unknown descriptor property was accepted")
	}
	if err = os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = readReviewedDescriptor(path, false); err == nil {
		t.Fatal("weak descriptor mode was accepted")
	}
	if err = os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "descriptor-link.json")
	if err = os.Symlink(path, link); err == nil {
		if _, err = readReviewedDescriptor(link, false); err == nil {
			t.Fatal("descriptor symlink was accepted")
		}
	}
}
