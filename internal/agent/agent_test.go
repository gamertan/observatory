// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/agentstate"
	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/hostmetrics"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
	"gamertan.com/observatory/internal/spool"
	"gamertan.com/observatory/internal/storage"
)

type fakeSender struct {
	fail         bool
	failAlerts   bool
	batchDigests map[uint64]string
	sent         []uint64
	alerts       []model.AlertTransition
}

func (sender *fakeSender) SendAlertTransition(_ context.Context, transition model.AlertTransition) (storage.SourceAlertTransitionAck, error) {
	if sender.failAlerts {
		return storage.SourceAlertTransitionAck{}, errors.New("alert endpoint unavailable")
	}
	sender.alerts = append(sender.alerts, transition)
	digest, err := transition.Digest()
	if err != nil {
		return storage.SourceAlertTransitionAck{}, err
	}
	return storage.SourceAlertTransitionAck{SourceID: "source", RuleID: transition.RuleID, RuleRevision: transition.RuleRevision, AgentEpoch: transition.AgentEpoch, Sequence: transition.Sequence, Digest: digest}, nil
}

func (sender *fakeSender) Send(_ context.Context, batch model.Batch) (storage.Ack, error) {
	if sender.fail {
		return storage.Ack{}, errors.New("server unavailable")
	}
	sender.sent = append(sender.sent, batch.Sequence)
	batchDigest, err := batch.Digest()
	if err != nil {
		return storage.Ack{}, err
	}
	if override := sender.batchDigests[batch.Sequence]; override != "" {
		batchDigest = override
	}
	return storage.Ack{SourceID: batch.SourceID, StreamID: batch.StreamID, Sequence: batch.Sequence, Digest: strings.Repeat("d", 64), BatchDigest: batchDigest}, nil
}

func TestRunnerCollectsWhileOfflineAndRecoversCheckpoint(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "request.jsonl")
	if err := os.WriteFile(logPath, []byte(requestLine("one")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(root, "spool")
	configuration := config.Agent{BatchRecords: 1, MaxSpoolBytes: 1 << 20, MaxSpoolAge: 72 * time.Hour, SpoolDir: spoolRoot, StateFile: filepath.Join(spoolRoot, "state.json"), Sources: []config.AgentSource{{Kind: "requestlog_jsonl", Path: logPath, StreamID: "request"}}}
	stateStore, state, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(spoolRoot, configuration.MaxSpoolBytes, configuration.MaxSpoolAge)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{fail: true}
	runner, err := New(configuration, "source", stateStore, state, queue, sender)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC)
	if err = runner.RunOnce(context.Background(), now); err == nil {
		t.Fatal("offline delivery unexpectedly succeeded")
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(requestLine("two") + "\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err = runner.RunOnce(context.Background(), now.Add(time.Second)); err == nil {
		t.Fatal("offline delivery unexpectedly succeeded")
	}
	entries, err := queue.List(now.Add(time.Second))
	if err != nil || len(entries) != 2 || entries[0].Sequence != 1 || entries[1].Sequence != 2 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	// Simulate a crash after both durable spool commits but before either cursor
	// checkpoint reached the state file. Recovery must advance state from the
	// spool envelopes before it reads the source again.
	empty := agentstate.State{Version: agentstate.Version, Streams: map[string]agentstate.Cursor{}}
	if err = stateStore.Save(empty); err != nil {
		t.Fatal(err)
	}
	_, recoveredState, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	sender.fail = false
	restarted, err := New(configuration, "source", stateStore, recoveredState, queue, sender)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.RunOnce(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 2 || sender.sent[0] != 1 || sender.sent[1] != 2 {
		t.Fatalf("sent=%v", sender.sent)
	}
	if entries, err = queue.List(now.Add(2 * time.Second)); err != nil || len(entries) != 0 {
		t.Fatalf("remaining=%+v err=%v", entries, err)
	}
	_, finalState, err := agentstate.Open(configuration.StateFile)
	if err != nil || finalState.Streams["request"].Sequence != 2 {
		t.Fatalf("state=%+v err=%v", finalState, err)
	}
}

func TestRunnerPreservesSpoolOnMismatchedAcknowledgement(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "request.jsonl")
	if err := os.WriteFile(logPath, []byte(requestLine("one")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(root, "spool")
	configuration := config.Agent{BatchRecords: 1, MaxSpoolBytes: 1 << 20, MaxSpoolAge: 72 * time.Hour, SpoolDir: spoolRoot, StateFile: filepath.Join(spoolRoot, "state.json"), Sources: []config.AgentSource{{Kind: "requestlog_jsonl", Path: logPath, StreamID: "request"}}}
	stateStore, state, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(spoolRoot, configuration.MaxSpoolBytes, configuration.MaxSpoolAge)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{batchDigests: map[uint64]string{1: strings.Repeat("a", 64)}}
	runner, err := New(configuration, "source", stateStore, state, queue, sender)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC)
	if err = runner.RunOnce(context.Background(), now); err == nil || !strings.Contains(err.Error(), "acknowledgement does not match exact batch") {
		t.Fatalf("expected exact acknowledgement rejection, got %v", err)
	}
	entries, err := queue.List(now)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

func TestRunnerDeliversLocallyEvaluatedAlertAfterRawBatchAcknowledgement(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "request.jsonl")
	if err := os.WriteFile(logPath, []byte(requestLineWithStatus("failed", 503)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(root, "spool")
	ast, err := query.Parse("logs | where status >= 500 | limit 10", model.MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	configuration := config.Agent{BatchRecords: 10, MaxSpoolBytes: 1 << 20, MaxSpoolAge: time.Hour, SpoolDir: spoolRoot, StateFile: filepath.Join(spoolRoot, "state.json"), Sources: []config.AgentSource{{Kind: "requestlog_jsonl", Path: logPath, StreamID: "request"}}, AlertRules: []config.AgentAlertRule{{Version: 1, ID: "http-failures", Revision: 1, StreamID: "request", Query: "logs | where status >= 500 | limit 10", MinimumMatches: 1, AST: ast}}}
	stateStore, state, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(spoolRoot, configuration.MaxSpoolBytes, configuration.MaxSpoolAge)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{}
	runner, err := New(configuration, "source", stateStore, state, queue, sender)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC)
	if err = runner.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 || len(sender.alerts) != 1 || sender.alerts[0].State != "matched" || sender.alerts[0].Sequence != 1 || sender.alerts[0].SegmentDigest != strings.Repeat("d", 64) || len(sender.alerts[0].AgentEpoch) != 32 {
		t.Fatalf("sent=%v alerts=%+v", sender.sent, sender.alerts)
	}
	if entries, listErr := queue.List(now); listErr != nil || len(entries) != 0 {
		t.Fatalf("entries=%+v err=%v", entries, listErr)
	}
}

func TestRunnerRetainsRawBatchUntilAlertTransitionIsAcknowledged(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "request.jsonl")
	if err := os.WriteFile(logPath, []byte(requestLineWithStatus("failed", 503)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(root, "spool")
	ast, err := query.Parse("logs | where status >= 500 | limit 10", model.MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	configuration := config.Agent{BatchRecords: 10, MaxSpoolBytes: 1 << 20, MaxSpoolAge: time.Hour, SpoolDir: spoolRoot, StateFile: filepath.Join(spoolRoot, "state.json"), Sources: []config.AgentSource{{Kind: "requestlog_jsonl", Path: logPath, StreamID: "request"}}, AlertRules: []config.AgentAlertRule{{Version: 1, ID: "http-failures", Revision: 1, StreamID: "request", Query: "logs | where status >= 500 | limit 10", MinimumMatches: 1, AST: ast}}}
	stateStore, state, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(spoolRoot, configuration.MaxSpoolBytes, configuration.MaxSpoolAge)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{failAlerts: true}
	runner, err := New(configuration, "source", stateStore, state, queue, sender)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC)
	if err = runner.RunOnce(context.Background(), now); err == nil || !strings.Contains(err.Error(), "alert endpoint unavailable") {
		t.Fatalf("err=%v", err)
	}
	if entries, listErr := queue.List(now); listErr != nil || len(entries) != 1 {
		t.Fatalf("entries=%+v err=%v", entries, listErr)
	}
	sender.failAlerts = false
	if err = runner.RunOnce(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 2 || len(sender.alerts) != 1 {
		t.Fatalf("sent=%v alerts=%+v", sender.sent, sender.alerts)
	}
}

func TestSourceIDParsingKeepsDotsInsideIdentifier(t *testing.T) {
	id, err := sourceIDFromCredential("obs1.node.example.abcdef")
	if err != nil || id != "node.example" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	for _, invalid := range []string{"token", "obs1..secret", "obs1.bad value.secret"} {
		if _, err = sourceIDFromCredential(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestRunnerSpoolsLinuxMetricsWhileServerIsOffline(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"stat": "cpu 1 2 3 4\n", "uptime": "10 5\n",
		"meminfo": "MemTotal: 10 kB\nMemAvailable: 8 kB\nSwapTotal: 2 kB\nSwapFree: 1 kB\n",
		"loadavg": "0.1 0.2 0.3 1/1 1\n", filepath.Join("net", "dev"): "Inter-| Receive | Transmit\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(proc, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spoolRoot := filepath.Join(root, "spool")
	configuration := config.Agent{BatchRecords: 3, MaxSpoolBytes: 1 << 20, MaxSpoolAge: time.Hour, SpoolDir: spoolRoot, StateFile: filepath.Join(spoolRoot, "state.json"), Sources: []config.AgentSource{{Kind: "linux_metrics", StreamID: "host-metrics", LinuxMetrics: &hostmetrics.Config{ProcRoot: proc}}}}
	stateStore, state, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(spoolRoot, configuration.MaxSpoolBytes, configuration.MaxSpoolAge)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(configuration, "source", stateStore, state, queue, &fakeSender{fail: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC)
	if err = runner.RunOnce(context.Background(), now); err == nil {
		t.Fatal("offline delivery unexpectedly succeeded")
	}
	entries, err := queue.List(now)
	if err != nil || len(entries) < 2 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	for index, entry := range entries {
		batch, _, readErr := queue.ReadWithCheckpoint(entry)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if batch.Signal != model.SignalMetrics || batch.StreamID != "host-metrics" || len(batch.Records) == 0 || len(batch.Records) > configuration.BatchRecords || batch.Sequence != uint64(index+1) {
			t.Fatalf("batch=%+v", batch)
		}
	}
}

func requestLine(route string) string {
	return `{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/` + route + `","status":200,"bytes":12,"duration_ns":1000,"request_id":"request-1"}`
}

func requestLineWithStatus(route string, status int) string {
	return fmt.Sprintf(`{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/%s","status":%d,"bytes":12,"duration_ns":1000,"request_id":"request-1"}`, route, status)
}
