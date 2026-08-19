// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadServerStrictAndValidated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	body := `{"schema":1,"listen":"127.0.0.1:9010","public_url":"https://observatory.example","data_dir":"` + filepath.Join(dir, "data") + `","max_body_bytes":1048576,"session_lifetime":"12h","query":{"max_duration":"2s","max_rows":1000,"max_scanned_bytes":10485760,"max_memory_bytes":8388608},"retention":{"raw_logs_days":30,"raw_traces_days":30,"raw_metrics_days":14,"cold_raw_days":400,"metric_rollups_days":400,"evidence_days":400}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(path, FilePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Query.MaxDuration.String() != "2s" || cfg.MaxConcurrentIngest != 8 || cfg.Retention.EvidenceDays != 400 || cfg.Retention.DeleteColdRaw {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	deleting := strings.Replace(body, `"cold_raw_days":400`, `"cold_raw_days":400,"delete_cold_raw":true`, 1)
	if err = os.WriteFile(path, []byte(deleting), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err = LoadServer(path, FilePolicy{}); err != nil || !cfg.Retention.DeleteColdRaw {
		t.Fatalf("explicit cold deletion config=%#v err=%v", cfg.Retention, err)
	}

	bad := strings.Replace(body, `"schema":1`, `"schema":1,"surprise":true`, 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(path, FilePolicy{}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
	bad = strings.Replace(body, `"max_body_bytes":1048576`, `"max_body_bytes":1048576,"max_concurrent_ingest":65`, 1)
	if err = os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadServer(path, FilePolicy{}); err == nil || !strings.Contains(err.Error(), "max_concurrent_ingest") {
		t.Fatalf("expected ingestion concurrency rejection, got %v", err)
	}
}

func TestDogfoodServerConfigurationMatchesTheDeploymentBoundary(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "release", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "web-push.json")
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = WriteWebPushPrivateKey(keyPath, key.Bytes()); err != nil {
		t.Fatal(err)
	}
	const runtimeKey = "/run/credentials/gamertan-observatory.service/web-push.json"
	rewritten := strings.Replace(string(body), runtimeKey, keyPath, 1)
	if rewritten == string(body) || strings.Contains(rewritten, runtimeKey) {
		t.Fatal("dogfood Web Push credential path was not replaced exactly once")
	}
	path := filepath.Join(dir, "server.json")
	if err = os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(path, FilePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8093" || cfg.PublicURL != "https://observatory.gamertan.com" || cfg.DataDir != "/var/lib/gamertan-observatory" || cfg.MaxBodyBytes != 32<<20 || cfg.MaxConcurrentIngest != 8 || cfg.Retention.DeleteColdRaw || cfg.WebPush == nil || cfg.WebPush.Subject != "mailto:security@sandwichhime.com" || cfg.WebPush.QueueCapacity != 64 || cfg.WebPush.Timeout != 10*time.Second || string(cfg.WebPush.PrivateKey) != string(key.Bytes()) {
		t.Fatalf("unexpected dogfood config: %#v", cfg)
	}
}

func TestLoadServerRejectsRollupsShorterThanRawMetrics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	body := `{"schema":1,"listen":"127.0.0.1:9010","public_url":"https://observatory.example","data_dir":"` + filepath.Join(dir, "data") + `","max_body_bytes":1048576,"session_lifetime":"12h","query":{"max_duration":"2s","max_rows":1000,"max_scanned_bytes":10485760,"max_memory_bytes":8388608},"retention":{"raw_logs_days":30,"raw_traces_days":30,"raw_metrics_days":14,"cold_raw_days":400,"metric_rollups_days":7,"evidence_days":400}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(path, FilePolicy{}); err == nil || !strings.Contains(err.Error(), "cannot be shorter") {
		t.Fatalf("short metric rollup retention err=%v", err)
	}
}

func TestLoadServerRejectsColdWindowShorterThanHotEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	body := `{"schema":1,"listen":"127.0.0.1:9010","public_url":"https://observatory.example","data_dir":"` + filepath.Join(dir, "data") + `","max_body_bytes":1048576,"session_lifetime":"12h","query":{"max_duration":"2s","max_rows":1000,"max_scanned_bytes":10485760,"max_memory_bytes":8388608},"retention":{"raw_logs_days":30,"raw_traces_days":30,"raw_metrics_days":14,"cold_raw_days":399,"metric_rollups_days":400,"evidence_days":400}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(path, FilePolicy{}); err == nil || !strings.Contains(err.Error(), "cold raw retention") {
		t.Fatalf("short cold retention err=%v", err)
	}
}

func TestLoadServerWebPushUsesSeparatePrivateKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "web-push.json")
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = WriteWebPushPrivateKey(keyPath, key.Bytes()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.json")
	body := `{"schema":1,"listen":"127.0.0.1:9010","public_url":"https://observatory.example","data_dir":"` + filepath.Join(dir, "data") + `","max_body_bytes":1048576,"session_lifetime":"12h","query":{"max_duration":"2s","max_rows":1000,"max_scanned_bytes":10485760,"max_memory_bytes":8388608},"retention":{"raw_logs_days":30,"raw_traces_days":30,"raw_metrics_days":14,"cold_raw_days":400,"metric_rollups_days":400,"evidence_days":400},"web_push":{"private_key_file":"` + keyPath + `","subject":"mailto:security@sandwichhime.com","queue_capacity":16,"request_timeout":"5s"}}`
	if err = os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(path, FilePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebPush == nil || cfg.WebPush.Timeout != 5*time.Second || cfg.WebPush.QueueCapacity != 16 || string(cfg.WebPush.PrivateKey) != string(key.Bytes()) {
		t.Fatalf("web push=%+v", cfg.WebPush)
	}
	if err = os.WriteFile(keyPath, []byte(`{"private_key":"not-a-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadServer(path, FilePolicy{}); err == nil {
		t.Fatal("invalid Web Push private key accepted")
	}
}

func TestLoadServerRejectsModeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(path, FilePolicy{}); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected mode rejection, got %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadServer(link, FilePolicy{}); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestLoadAgentKeepsSourcesLocalAndBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	body := `{"schema":1,"server_url":"https://observatory.example","credential_file":"` + filepath.Join(dir, "credential.json") + `","spool_dir":"` + filepath.Join(dir, "spool") + `","state_file":"` + filepath.Join(dir, "spool", "state.json") + `","max_spool_bytes":5368709120,"max_spool_age":"72h","batch_records":500,"flush_interval":"1s","sources":[{"kind":"caddy_json","path":"/var/log/caddy/access.jsonl","stream_id":"caddy","sensitive_fields":["client_ip","query","referrer","user_agent"]}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgent(path, FilePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxSpoolAge != 72*time.Hour || cfg.FlushEvery != time.Second || cfg.Sources[0].Path != "/var/log/caddy/access.jsonl" || len(cfg.Sources[0].SensitiveFields) != 4 {
		t.Fatalf("agent=%+v", cfg)
	}
	bad := strings.Replace(body, `"kind":"caddy_json"`, `"kind":"shell"`, 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgent(path, FilePolicy{}); err == nil {
		t.Fatal("expected collector-kind rejection")
	}
	for _, change := range [][2]string{
		{`"sensitive_fields":["client_ip","query","referrer","user_agent"]`, `"sensitive_fields":["client_ip","client_ip"]`},
		{`"sensitive_fields":["client_ip","query","referrer","user_agent"]`, `"sensitive_fields":["cookie"]`},
		{`"kind":"caddy_json"`, `"kind":"tend_events_jsonl"`},
	} {
		candidate := strings.Replace(body, change[0], change[1], 1)
		if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAgent(path, FilePolicy{}); err == nil {
			t.Fatalf("invalid sensitive-field configuration accepted: %s", change[1])
		}
	}
}

func TestLoadAgentAcceptsExplicitLinuxMetricSelectors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	body := `{"schema":1,"server_url":"https://observatory.example","credential_file":"` + filepath.Join(dir, "credential.json") + `","spool_dir":"` + filepath.Join(dir, "spool") + `","state_file":"` + filepath.Join(dir, "spool", "state.json") + `","max_spool_bytes":1048576,"max_spool_age":"1h","batch_records":500,"flush_interval":"1s","sources":[{"kind":"linux_metrics","stream_id":"host-metrics","linux_metrics":{"proc_root":"/proc","cgroup_root":"/sys/fs/cgroup","filesystems":[{"name":"root","path":"/"}],"processes":[{"name":"caddy","pid_file":"/run/caddy.pid"}],"cgroups":[{"name":"caddy-service","path":"system.slice/caddy.service"}]}}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgent(path, FilePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources[0].LinuxMetrics == nil || cfg.Sources[0].LinuxMetrics.Filesystems[0].Name != "root" {
		t.Fatalf("agent=%+v", cfg)
	}
	bad := strings.Replace(body, `"path":"system.slice/caddy.service"`, `"path":"../escape"`, 1)
	if err = os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadAgent(path, FilePolicy{}); err == nil {
		t.Fatal("escaping cgroup selector accepted")
	}
}

func TestLoadAgentAcceptsOnlyLocalBoundedLogAlertRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	body := `{"schema":1,"server_url":"https://observatory.example","credential_file":"` + filepath.Join(dir, "credential.json") + `","spool_dir":"` + filepath.Join(dir, "spool") + `","state_file":"` + filepath.Join(dir, "spool", "state.json") + `","max_spool_bytes":1048576,"max_spool_age":"1h","batch_records":500,"flush_interval":"1s","sources":[{"kind":"requestlog_jsonl","path":"/var/log/example/request.jsonl","stream_id":"requests"}],"alert_rules":[{"version":1,"id":"http-failures","revision":2,"stream_id":"requests","query":"logs | where status >= 500 | limit 10","minimum_matches":1}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgent(path, FilePolicy{})
	if err != nil || len(cfg.AlertRules) != 1 || cfg.AlertRules[0].AST.Signal != "logs" || len(cfg.AlertRules[0].AST.Filters) != 1 {
		t.Fatalf("agent=%+v err=%v", cfg, err)
	}
	for _, replacement := range []string{
		`"stream_id":"missing"`,
		`"query":"metrics | where value > 0 | limit 10"`,
		`"query":"logs | summarize count() | limit 10"`,
		`"query":"logs | where service == other | limit 10"`,
		`"minimum_matches":11`,
	} {
		candidate := body
		switch {
		case strings.Contains(replacement, "missing"):
			candidate = strings.Replace(candidate, `"stream_id":"requests","query"`, replacement+`,"query"`, 1)
		case strings.HasPrefix(replacement, `"query"`):
			candidate = strings.Replace(candidate, `"query":"logs | where status >= 500 | limit 10"`, replacement, 1)
		default:
			candidate = strings.Replace(candidate, `"minimum_matches":1`, replacement, 1)
		}
		if err = os.WriteFile(path, []byte(candidate), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err = LoadAgent(path, FilePolicy{}); err == nil {
			t.Fatalf("invalid alert rule accepted: %s", replacement)
		}
	}
}

func TestLoadCredentialDoesNotAcceptWhitespaceOrExtraFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	valid := `{"credential":"obs1.source.` + strings.Repeat("a", 64) + `"}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if credential, err := LoadCredential(path, FilePolicy{}); err != nil || !strings.HasPrefix(credential, "obs1.source.") {
		t.Fatalf("credential=%q err=%v", credential, err)
	}
	if err := os.WriteFile(path, []byte(`{"credential":"obs1.source.bad value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(path, FilePolicy{}); err == nil {
		t.Fatal("expected whitespace rejection")
	}
}

func TestEnrollmentAndCredentialOutputsArePrivateAndExclusive(t *testing.T) {
	dir := t.TempDir()
	enrollmentPath := filepath.Join(dir, "enrollment.json")
	enrollment := "obse1." + strings.Repeat("e", 64)
	if err := WriteEnrollmentToken(enrollmentPath, enrollment); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadEnrollmentToken(enrollmentPath, FilePolicy{}); err != nil || got != enrollment {
		t.Fatalf("token=%q err=%v", got, err)
	}
	if err := WriteEnrollmentToken(enrollmentPath, enrollment); err == nil {
		t.Fatal("enrollment output overwritten")
	}
	credentialPath := filepath.Join(dir, "credential.json")
	credential := "obs1.source." + strings.Repeat("a", 64)
	if err := WriteCredential(credentialPath, credential); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadCredential(credentialPath, FilePolicy{}); err != nil || got != credential {
		t.Fatalf("credential=%q err=%v", got, err)
	}
	for _, path := range []string{enrollmentPath, credentialPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("path=%s info=%v err=%v", path, info, err)
		}
	}
}

func TestSystemdCredentialPolicyIsExplicitAndConfined(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	policy, err := SystemdCredentialPolicy()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential.json")
	credential := `{"credential":"obs1.source.` + strings.Repeat("a", 64) + `"}`
	if err := os.WriteFile(path, []byte(credential), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(path, policy); err != nil {
		t.Fatalf("load systemd credential: %v", err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(path, policy); err != nil {
		t.Fatalf("load systemd mode-0440 credential: %v", err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(path, policy); err == nil || !strings.Contains(err.Error(), "0400, 0440, or 0600") {
		t.Fatalf("expected public credential mode rejection, got %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(outside, []byte(credential), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(outside, policy); err == nil || !strings.Contains(err.Error(), "direct child") {
		t.Fatalf("expected confinement rejection, got %v", err)
	}

	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedPath := filepath.Join(nested, "credential.json")
	if err := os.WriteFile(nestedPath, []byte(credential), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(nestedPath, policy); err == nil || !strings.Contains(err.Error(), "direct child") {
		t.Fatalf("expected nested-path rejection, got %v", err)
	}
}
