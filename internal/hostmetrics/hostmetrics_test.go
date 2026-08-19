// SPDX-License-Identifier: AGPL-3.0-only

package hostmetrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/observatory/internal/model"
)

func TestCollectReadsOnlyConfiguredLinuxEvidence(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	cgroup := filepath.Join(root, "cgroup")
	filesystem := filepath.Join(root, "filesystem")
	pidFile := filepath.Join(root, "service.pid")
	for _, directory := range []string{filepath.Join(proc, "net"), filepath.Join(proc, "123"), filepath.Join(cgroup, "system.slice", "example.service"), filesystem} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(proc, "stat"), "cpu 100 2 30 400 5 6 7 8 9 10\n")
	write(filepath.Join(proc, "uptime"), "99.5 80.0\n")
	write(filepath.Join(proc, "meminfo"), "MemTotal: 1000 kB\nMemAvailable: 750 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")
	write(filepath.Join(proc, "loadavg"), "0.10 0.20 0.30 1/100 123\n")
	write(filepath.Join(proc, "net", "dev"), "Inter-| Receive | Transmit\nlo: 100 2 0 1 0 0 0 0 200 3 0 2 0 0 0 0\n")
	write(pidFile, "123\n")
	write(filepath.Join(proc, "123", "stat"), "123 (example worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23\n")
	write(filepath.Join(proc, "123", "io"), "read_bytes: 4096\nwrite_bytes: 8192\n")
	group := filepath.Join(cgroup, "system.slice", "example.service")
	write(filepath.Join(group, "memory.current"), "1024\n")
	write(filepath.Join(group, "memory.peak"), "2048\n")
	write(filepath.Join(group, "memory.swap.current"), "0\n")
	write(filepath.Join(group, "pids.current"), "3\n")
	write(filepath.Join(group, "cpu.stat"), "usage_usec 300\nuser_usec 200\nsystem_usec 100\n")
	write(filepath.Join(group, "io.stat"), "8:0 rbytes=100 wbytes=200 rios=1 wios=2\n8:1 rbytes=300 wbytes=400 rios=3 wios=4\n")

	configuration := Config{
		ProcRoot: proc, CgroupRoot: cgroup,
		Filesystems:   []Filesystem{{Name: "data", Path: filesystem}},
		Processes:     []Process{{Name: "web", PIDFile: pidFile}},
		ControlGroups: []Cgroup{{Name: "web-service", Path: filepath.Join("system.slice", "example.service")}},
	}
	now := time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC)
	observations, err := Collect(configuration, now)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"system.cpu.time_ticks": false, "system.memory": false, "system.load.average": false,
		"system.network.bytes": false, "system.filesystem.bytes": false, "process.up": false,
		"process.start_time_ticks": false, "process.io.bytes": false, "cgroup.up": false, "cgroup.io.bytes": false,
	}
	for _, observation := range observations {
		if _, ok := wanted[observation.Name]; ok {
			wanted[observation.Name] = true
		}
		for _, value := range observation.Attributes {
			if strings.Contains(value, root) {
				t.Fatalf("local path leaked in attributes: %+v", observation)
			}
		}
		if _, found := observation.Attributes["start_ticks"]; found {
			t.Fatalf("dynamic process identity leaked into metric attributes: %+v", observation)
		}
	}
	for name, found := range wanted {
		if !found {
			t.Errorf("missing %s", name)
		}
	}
	batch := model.Batch{Version: model.BatchVersion, SourceID: "source", StreamID: "host-metrics", Sequence: 1, ObservedAt: now, Signal: model.SignalMetrics, Records: observations}
	if err = batch.Validate(now); err != nil {
		t.Fatalf("collected batch: %v", err)
	}
}

func TestCollectRejectsSymlinkMetricSource(t *testing.T) {
	proc := createMinimalProc(t)
	target := filepath.Join(t.TempDir(), "pid")
	if err := os.WriteFile(target, []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "selected.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	observations, err := Collect(Config{ProcRoot: proc, Processes: []Process{{Name: "selected", PIDFile: link}}}, time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("symlink PID source accepted without a collection warning")
	}
	for _, observation := range observations {
		if observation.Name == "process.up" && observation.Value != nil && *observation.Value == 0 {
			return
		}
	}
	t.Fatal("rejected symlink source did not retain process.up=0 evidence")
}

func TestCollectReportsMissingSelectedProcessWithoutDroppingHostMetrics(t *testing.T) {
	proc := createMinimalProc(t)
	now := time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC)
	observations, err := Collect(Config{ProcRoot: proc, Processes: []Process{{Name: "missing", PIDFile: filepath.Join(t.TempDir(), "missing.pid")}}}, now)
	if err == nil || len(observations) == 0 {
		t.Fatalf("observations=%d err=%v", len(observations), err)
	}
	foundDown := false
	for _, observation := range observations {
		if observation.Name == "process.up" && observation.Value != nil && *observation.Value == 0 {
			foundDown = true
		}
	}
	if !foundDown {
		t.Fatal("missing process did not emit process.up=0")
	}
}

func TestValidationRejectsEscapingAndDuplicateSelectors(t *testing.T) {
	root := t.TempDir()
	for _, configuration := range []Config{
		{ProcRoot: "relative"},
		{ProcRoot: root, CgroupRoot: root, ControlGroups: []Cgroup{{Name: "bad", Path: "../escape"}}},
		{ProcRoot: root, Filesystems: []Filesystem{{Name: "same", Path: root}}, Processes: []Process{{Name: "same", PIDFile: filepath.Join(root, "pid")}}},
	} {
		if err := configuration.Validate(); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", configuration)
		}
	}
}

func createMinimalProc(t *testing.T) string {
	t.Helper()
	proc := filepath.Join(t.TempDir(), "proc")
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"stat": "cpu 1 1 1 1\n", "uptime": "1 1\n",
		"meminfo": "MemTotal: 1 kB\nMemAvailable: 1 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
		"loadavg": "0 0 0 1/1 1\n", filepath.Join("net", "dev"): "Inter-| Receive | Transmit\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(proc, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return proc
}
