// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"gamertan.com/observatory/internal/config"
)

func TestReleaseWebPushUsesAServiceScopedSystemdCredential(t *testing.T) {
	serverBody, err := os.ReadFile("../../release/server.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(serverBody))
	decoder.DisallowUnknownFields()
	var server config.Server
	if err = decoder.Decode(&server); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatal("release server configuration contains trailing JSON")
	}
	const runtimeKey = "/run/credentials/gamertan-observatory.service/web-push.json"
	if server.MaxBodyBytes != 32<<20 || server.MaxConcurrentIngest != 8 || server.WebPush == nil || server.WebPush.PrivateKeyFile != runtimeKey || server.WebPush.Subject != "mailto:security@sandwichhime.com" || server.WebPush.QueueCapacity != 64 || server.WebPush.RequestTimeout != "10s" {
		t.Fatalf("web push release configuration=%+v", server.WebPush)
	}

	unitBody, err := os.ReadFile("../../release/observatory.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(unitBody)
	for _, required := range []string{
		"LoadCredential=server.json:/etc/gamertan-observatory/server.json",
		"LoadCredential=web-push.json:/etc/gamertan-observatory/web-push.json",
		"ExecStart=/opt/gamertan-observatory/current/observatory server --config %d/server.json --systemd-credential-config",
	} {
		if strings.Count(unit, required) != 1 {
			t.Fatalf("release unit requires one %q", required)
		}
	}
	if bytes.Contains(serverBody, []byte("private_key\"")) || bytes.Contains(serverBody, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("release server configuration contains private-key material")
	}
}

func TestReleaseCaddyAccessLogIsFilteredAndBounded(t *testing.T) {
	body, err := os.ReadFile("../../release/Caddyfile.observatory")
	if err != nil {
		t.Fatal(err)
	}
	configuration := string(body)
	for _, required := range []string{
		"log observatory_access {",
		"output file /var/log/caddy/observatory-access.jsonl {",
		"mode 0640",
		"roll_size 100mb",
		"roll_keep 10",
		"roll_keep_for 720h",
		`request>uri regexp \?.*$ ""`,
		"request>remote_ip delete",
		"request>remote_port delete",
		"request>client_ip delete",
		"request>headers delete",
		"resp_headers delete",
		"user_id delete",
		"log_append request_id {http.response.header.X-Request-ID}",
	} {
		if strings.Count(configuration, required) != 1 {
			t.Fatalf("release Caddy configuration requires one %q", required)
		}
	}
	for _, forbidden := range []string{"log_credentials", "Cookie", "Authorization", "query {"} {
		if strings.Contains(configuration, forbidden) {
			t.Fatalf("release Caddy configuration contains forbidden %q", forbidden)
		}
	}
}

func TestReleaseAgentIsUnprivilegedScopedAndPrivacyMinimized(t *testing.T) {
	body, err := os.ReadFile("../../release/agent.json")
	if err != nil {
		t.Fatal(err)
	}
	testPath := t.TempDir() + "/agent.json"
	if err = os.WriteFile(testPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := config.LoadAgent(testPath, config.FilePolicy{})
	if err != nil {
		t.Fatalf("validate release agent configuration: %v", err)
	}
	if agent.Schema != 1 || agent.ServerURL != "https://observatory.gamertan.com" || agent.CredentialFile != "/etc/gamertan-observatory/agent-credential.json" || agent.SpoolDir != "/var/lib/gamertan-observatory-agent" || agent.StateFile != "/var/lib/gamertan-observatory-agent/state.json" || agent.MaxSpoolBytes != 5<<30 || agent.MaxSpoolAgeText != "72h" || agent.BatchRecords != 5000 || agent.FlushInterval != "1s" {
		t.Fatalf("release agent configuration=%+v", agent)
	}
	if len(agent.Sources) != 6 {
		t.Fatalf("release agent source count=%d", len(agent.Sources))
	}
	wantSources := []struct{ kind, path, stream string }{
		{"caddy_json", "/var/log/caddy/eqlwiki-edge.jsonl", "eql-edge"},
		{"requestlog_jsonl", "/var/log/eqlwiki/access.jsonl", "eql-application"},
		{"tend_events_jsonl", "/opt/gamertancom/deployment-events.jsonl", "tend-gamertancom"},
		{"tend_events_jsonl", "/opt/sandwich-hime-site/deployment-events.jsonl", "tend-sandwich-hime-site"},
		{"tend_events_jsonl", "/opt/gamertan-observatory/deployment-events.jsonl", "tend-observatory"},
		{"linux_metrics", "", "public-node-host-metrics"},
	}
	for index, want := range wantSources {
		source := agent.Sources[index]
		if source.Kind != want.kind || source.Path != want.path || source.StreamID != want.stream || len(source.SensitiveFields) != 0 {
			t.Fatalf("release agent source[%d]=%+v", index, source)
		}
	}
	metrics := agent.Sources[5].LinuxMetrics
	if metrics == nil || metrics.ProcRoot != "/proc" || metrics.CgroupRoot != "/sys/fs/cgroup" || len(metrics.Filesystems) != 1 || metrics.Filesystems[0].Name != "root" || metrics.Filesystems[0].Path != "/" || len(metrics.ControlGroups) != 6 {
		t.Fatalf("release Linux metrics=%+v", metrics)
	}
	wantCgroups := map[string]string{
		"caddy":             "system.slice/caddy.service",
		"eql":               "system.slice/system-eqlwiki.slice",
		"gamertan":          "system.slice/system-gamertancom.slice",
		"sandwich-hime":     "system.slice/sandwich-hime-site.service",
		"observatory":       "system.slice/gamertan-observatory.service",
		"observatory-agent": "system.slice/gamertan-observatory-agent.service",
	}
	for _, selected := range metrics.ControlGroups {
		if wantCgroups[selected.Name] != selected.Path {
			t.Fatalf("unexpected release cgroup selector=%+v", selected)
		}
		delete(wantCgroups, selected.Name)
	}
	if len(wantCgroups) != 0 {
		t.Fatalf("missing release cgroup selectors=%v", wantCgroups)
	}
	if bytes.Contains(body, []byte("observatory-access")) || bytes.Contains(body, []byte("sensitive_fields")) {
		t.Fatal("release agent enables a feedback loop or sensitive evidence")
	}

	unitBody, err := os.ReadFile("../../release/observatory-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(unitBody)
	for _, required := range []string{
		"User=observatory-agent",
		"Group=observatory-agent",
		"SupplementaryGroups=caddy eqlwiki gamertancom",
		"PartOf=gamertan-observatory.service",
		"LoadCredential=agent.json:/etc/gamertan-observatory/agent.json",
		"LoadCredential=agent-credential.json:/etc/gamertan-observatory/agent-credential.json",
		"ExecStart=/opt/gamertan-observatory/current/observatory agent --systemd-credentials --config %d/agent.json --credential-file %d/agent-credential.json",
		"StateDirectory=gamertan-observatory-agent",
		"StateDirectoryMode=0700",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectProc=invisible",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"ReadOnlyPaths=/proc /sys/fs/cgroup /var/log/caddy /var/log/eqlwiki /opt/gamertancom/deployment-events.jsonl /opt/sandwich-hime-site/deployment-events.jsonl /opt/gamertan-observatory/deployment-events.jsonl",
		"ReadWritePaths=/var/lib/gamertan-observatory-agent",
		"MemoryMax=256M",
	} {
		if strings.Count(unit, required) != 1 {
			t.Fatalf("release agent unit requires one %q", required)
		}
	}
	for _, forbidden := range []string{"User=root", "docker.sock", "sh -c", "curl ", "wget ", "PrivateNetwork=yes"} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("release agent unit contains forbidden %q", forbidden)
		}
	}
}

func TestSensitiveCaddyExampleKeepsAnExplicitProducerBoundary(t *testing.T) {
	body, err := os.ReadFile("../../examples/Caddyfile.sensitive-access-log")
	if err != nil {
		t.Fatal(err)
	}
	configuration := string(body)
	for _, required := range []string{
		"mode 0640",
		"roll_size 100mb",
		"roll_keep 10",
		"roll_keep_for 720h",
		"request>uri query {",
		"delete access_token",
		"delete api_key",
		"delete authorization",
		"delete code",
		"delete credential",
		"delete key",
		"delete password",
		"delete secret",
		"\n\t\t\t\tdelete session\n",
		"delete session_id",
		"delete token",
		"client_ip ip_mask 24 56",
		"request>remote_ip delete",
		"request>remote_port delete",
		"request>client_ip delete",
		"request>headers delete",
		"resp_headers delete",
		"user_id delete",
		"log_append request_id {http.response.header.X-Request-ID}",
		"log_append client_ip {http.request.client_ip}",
		"log_append referrer {http.request.header.Referer}",
		"log_append user_agent {http.request.header.User-Agent}",
	} {
		if strings.Count(configuration, required) != 1 {
			t.Fatalf("sensitive Caddy example requires one %q", required)
		}
	}
	for _, forbidden := range []string{"log_credentials", "Cookie", "Authorization"} {
		if strings.Contains(configuration, forbidden) {
			t.Fatalf("sensitive Caddy example contains forbidden %q", forbidden)
		}
	}
}
