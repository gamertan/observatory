// SPDX-License-Identifier: AGPL-3.0-only

package tailer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/agentstate"
	"gamertan.com/observatory/internal/collector"
	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/model"
)

func TestTailerPreservesPartialLineAndRecoversRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.jsonl")
	first := requestLine("one") + "\n" + requestLine("two") + "\n"
	partial := `{"timestamp":"2026-08-17T01:02:03Z","method":"GET"`
	if err := os.WriteFile(path, []byte(first+partial), 0o640); err != nil {
		t.Fatal(err)
	}
	source := config.AgentSource{Kind: "requestlog_jsonl", Path: path, StreamID: "request"}
	now := time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC)
	result, err := Read(source, agentstate.Cursor{}, 10, now)
	if err != nil || len(result.Observations) != 2 || result.Cursor.Offset != int64(len(first)) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(`,"route":"/three","status":200}` + "\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	result, err = Read(source, result.Cursor, 10, now)
	if err != nil || len(result.Observations) != 1 || result.Observations[0].Attributes["http.route"] != "/three" {
		t.Fatalf("partial result=%+v err=%v", result, err)
	}
	cursor := result.Cursor
	file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(requestLine("before-rotate") + "\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err = os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(requestLine("new-file")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err = Read(source, cursor, 10, now)
	if err != nil || len(result.Observations) != 2 || result.Observations[0].Attributes["http.route"] != "/before-rotate" || result.Observations[1].Attributes["http.route"] != "/new-file" {
		t.Fatalf("rotation result=%+v err=%v", result, err)
	}
}

func TestTailerBoundsOversizedLinesAndDetectsTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.jsonl")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", collector.MaxLineBytes+100)), 0o640); err != nil {
		t.Fatal(err)
	}
	source := config.AgentSource{Kind: "requestlog_jsonl", Path: path, StreamID: "request"}
	now := time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC)
	result, err := Read(source, agentstate.Cursor{}, 10, now)
	if err != nil || !result.Cursor.DiscardingLine || result.Cursor.Offset != collector.MaxLineBytes+100 {
		t.Fatalf("oversized result=%+v err=%v", result, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString("\n" + requestLine("after-large") + "\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	result, err = Read(source, result.Cursor, 10, now)
	if err != nil || result.Cursor.DroppedRecords != 1 || len(result.Observations) != 1 {
		t.Fatalf("discard result=%+v err=%v", result, err)
	}
	if err = os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(requestLine("after-truncate")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err = Read(source, result.Cursor, 10, now)
	if err != nil || result.Cursor.Discontinuities != 1 || len(result.Observations) != 1 {
		t.Fatalf("truncate result=%+v err=%v", result, err)
	}
}

func TestTailerAcceptsBoundedLineLargerThanReaderBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.jsonl")
	line := `{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/large","status":200,"padding":"` + strings.Repeat("x", 128<<10) + `"}`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err := Read(config.AgentSource{Kind: "requestlog_jsonl", Path: path, StreamID: "request"}, agentstate.Cursor{}, 10, time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC))
	if err != nil || len(result.Observations) != 1 || result.Cursor.DroppedRecords != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTailerBoundsSourceBytesPerCycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.jsonl")
	line := `{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/bounded","status":200,"padding":"` + strings.Repeat("x", 256<<10) + `"}` + "\n"
	const lines = 20
	if err := os.WriteFile(path, []byte(strings.Repeat(line, lines)), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err := Read(config.AgentSource{Kind: "requestlog_jsonl", Path: path, StreamID: "request"}, agentstate.Cursor{}, model.MaxRecords, time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC))
	if err != nil || len(result.Observations) == 0 || len(result.Observations) >= lines || result.Cursor.Offset < maxReadBytesPerCycle-int64(len(line)) || result.Cursor.Offset > maxReadBytesPerCycle+int64(len(line)) {
		t.Fatalf("observations=%d offset=%d err=%v", len(result.Observations), result.Cursor.Offset, err)
	}
}

func TestTailerAppliesExplicitSensitiveFieldSelection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.jsonl")
	line := `{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/items","status":200,"client_ip":"192.0.2.25","query":"view=full"}`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	source := config.AgentSource{Kind: "requestlog_jsonl", Path: path, StreamID: "request", SensitiveFields: []string{"client_ip", "query"}}
	result, err := Read(source, agentstate.Cursor{}, 10, time.Date(2026, 8, 17, 1, 2, 4, 0, time.UTC))
	if err != nil || len(result.Observations) != 1 || result.Observations[0].Attributes["client.address"] != "192.0.2.25" || result.Observations[0].Attributes["url.query"] != "view=full" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTailerRejectsSymlinkSource(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte(requestLine("one")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	_, err := Read(config.AgentSource{Kind: "requestlog_jsonl", Path: link, StreamID: "request"}, agentstate.Cursor{}, 10, time.Now().UTC())
	if err == nil {
		t.Fatal("symlink source accepted")
	}
}

func requestLine(route string) string {
	return `{"timestamp":"2026-08-17T01:02:03Z","method":"GET","route":"/` + route + `","status":200,"bytes":12,"duration_ns":1000,"request_id":"request-1"}`
}
