// SPDX-License-Identifier: AGPL-3.0-only

package collector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCaddyCollectorDropsSecretsAndQuery(t *testing.T) {
	line := []byte(`{"ts":1720000000.25,"request":{"method":"GET","uri":"/search?q=secret","remote_ip":"192.0.2.10","headers":{"Cookie":["session=secret"],"Authorization":["Bearer secret"],"X-Request-Id":["req-123"]}},"status":200,"size":42,"duration":0.001}`)
	_, observation, err := Parse("caddy_json", line, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(observation)
	for _, forbidden := range []string{"q=secret", "session=secret", "Bearer secret", "192.0.2.10", "Authorization", "Cookie"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("secret escaped into observation: %s", b)
		}
	}
	if observation.Attributes["http.path"] != "/search" || observation.CorrelationID != "req-123" {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestCaddyCollectorUsesFilteredTopLevelRequestID(t *testing.T) {
	line := []byte(`{"ts":1720000000.25,"request_id":"response-request-123","client_ip":"192.0.2.45","referrer":"https://example.test/start?private=yes","user_agent":"example-agent","request":{"method":"GET","uri":"/items?view=private"},"status":200,"size":42,"duration":0.001}`)
	_, observation, err := Parse("caddy_json", line, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if observation.CorrelationID != "response-request-123" || observation.Attributes["request.id"] != "response-request-123" || observation.Attributes["http.path"] != "/items" {
		t.Fatalf("observation=%+v", observation)
	}
	for _, forbidden := range []string{"client.address", "url.query", "http.request.referrer", "user_agent.original"} {
		if _, ok := observation.Attributes[forbidden]; ok {
			t.Fatalf("default collection retained sensitive field %q", forbidden)
		}
	}
	_, observation, err = Parse("caddy_json", line, time.Unix(1, 0), "client_ip", "query", "referrer", "user_agent")
	if err != nil || observation.Attributes["client.address"] != "192.0.2.45" || observation.Attributes["url.query"] != "view=private" || observation.Attributes["http.request.referrer"] != "https://example.test/start?private=yes" || observation.Attributes["user_agent.original"] != "example-agent" {
		t.Fatalf("sensitive observation=%+v err=%v", observation, err)
	}

	line = []byte(`{"request_id":"invalid request id","request":{"method":"GET","uri":"/items","headers":{"X-Request-ID":["compatible-header-id"]}},"status":200}`)
	_, observation, err = Parse("caddy_json", line, time.Unix(1, 0))
	if err != nil || observation.CorrelationID != "compatible-header-id" {
		t.Fatalf("fallback observation=%+v err=%v", observation, err)
	}
}

func TestRequestLogCollectorUsesWhitelist(t *testing.T) {
	line := []byte(`{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/items/{id}","status":200,"request_id":"request-1","query":"view=full","client_ip":"192.0.2.2","referer":"https://example.test/start","user_agent":"example-agent","session_id":"anonymous-session","extra_secret":"nope"}`)
	_, observation, err := Parse("requestlog_jsonl", line, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(observation)
	if strings.Contains(string(b), "192.0.2.2") || strings.Contains(string(b), "view=full") || strings.Contains(string(b), "anonymous-session") || observation.Attributes["http.route"] != "/items/{id}" {
		t.Fatalf("observation=%s", b)
	}
	_, observation, err = Parse("requestlog_jsonl", line, time.Unix(1, 0), "client_ip", "query", "referrer", "user_agent", "session_id")
	if err != nil || observation.Attributes["client.address"] != "192.0.2.2" || observation.Attributes["url.query"] != "view=full" || observation.Attributes["http.request.referrer"] != "https://example.test/start" || observation.Attributes["user_agent.original"] != "example-agent" || observation.Attributes["session.id"] != "anonymous-session" {
		t.Fatalf("sensitive requestlog observation=%+v err=%v", observation, err)
	}
}

func TestTendCollectorIsStrict(t *testing.T) {
	line := []byte(`{"version":1,"operation_id":"0123456789abcdef0123456789abcdef","service":"site","artifact_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","release_version":"v0.2.0-preview.1","phase":"activation","slot":"green","duration_ms":25,"outcome":"succeeded","observed_at":"2026-08-17T01:02:03Z"}`)
	signal, observation, err := Parse("tend_events_jsonl", line, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if signal != "deployments" || observation.Attributes["deployment.outcome"] != "succeeded" || observation.CorrelationID != "0123456789abcdef0123456789abcdef" || len(observation.Attributes) != 9 {
		t.Fatalf("signal=%s observation=%+v", signal, observation)
	}
	if _, _, err := Parse("tend_events_jsonl", append(line[:len(line)-1], []byte(`,"secret":"x"}`)...), time.Unix(1, 0)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
	rollback := []byte(`{"version":1,"operation_id":"fedcba9876543210fedcba9876543210","service":"site","artifact_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","commit":"dddddddddddddddddddddddddddddddddddddddd","release_version":"v0.2.0-preview.1","phase":"rollback","slot":"blue","duration_ms":12,"outcome":"succeeded","observed_at":"2026-08-17T01:03:04.123Z"}`)
	_, observation, err = Parse("tend_events_jsonl", rollback, time.Unix(1, 0))
	if err != nil || observation.Attributes["deployment.phase"] != "rollback" || observation.Attributes["deployment.artifact"] != strings.Repeat("c", 64) {
		t.Fatalf("rollback observation=%+v err=%v", observation, err)
	}
	invalid := [][]byte{
		[]byte(strings.Replace(string(line), `"version":1`, `"version":2`, 1)),
		[]byte(strings.Replace(string(line), "0123456789abcdef0123456789abcdef", "short", 1)),
		[]byte(strings.Replace(string(line), strings.Repeat("a", 64), strings.Repeat("A", 64), 1)),
		[]byte(strings.Replace(string(line), strings.Repeat("b", 40), strings.Repeat("b", 39), 1)),
		[]byte(strings.Replace(string(line), `"service":"site"`, `"service":"unsafe service"`, 1)),
		[]byte(strings.Replace(string(line), `"duration_ms":25`, `"duration_ms":-1`, 1)),
		[]byte(strings.Replace(string(line), "2026-08-17T01:02:03Z", "not-a-time", 1)),
		append(append([]byte{}, line...), []byte(` {}`)...),
		[]byte(strings.Repeat(" ", 4097)),
	}
	for index, candidate := range invalid {
		if _, _, err := Parse("tend_events_jsonl", candidate, time.Unix(1, 0)); err == nil {
			t.Fatalf("invalid Tend event %d was accepted", index)
		}
	}
}

func FuzzTendCollector(f *testing.F) {
	f.Add([]byte(`{"version":1,"operation_id":"0123456789abcdef0123456789abcdef","service":"site","artifact_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","release_version":"v0.2.0-preview.1","phase":"activation","slot":"green","duration_ms":25,"outcome":"succeeded","observed_at":"2026-08-17T01:02:03Z"}`))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, line []byte) {
		signal, observation, err := Parse("tend_events_jsonl", line, time.Unix(1, 0))
		if err != nil {
			return
		}
		if signal != "deployments" || observation.Name != "tend.deployment" || observation.CorrelationID == "" || len(observation.Attributes) < 8 || len(observation.Attributes) > 9 {
			t.Fatalf("accepted event violated invariants: signal=%q observation=%+v", signal, observation)
		}
		allowed := map[string]bool{"deployment.operation_id": true, "service.name": true, "deployment.artifact": true, "deployment.commit": true, "deployment.version": true, "deployment.phase": true, "deployment.slot": true, "deployment.duration_ms": true, "deployment.outcome": true}
		for name := range observation.Attributes {
			if !allowed[name] {
				t.Fatalf("accepted unexpected attribute %q", name)
			}
		}
	})
}
