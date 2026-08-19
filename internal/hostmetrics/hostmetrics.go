// SPDX-License-Identifier: AGPL-3.0-only

package hostmetrics

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"gamertan.com/observatory/internal/model"
)

const maxSourceBytes = 1 << 20

type Config struct {
	ProcRoot      string       `json:"proc_root"`
	CgroupRoot    string       `json:"cgroup_root,omitempty"`
	Filesystems   []Filesystem `json:"filesystems,omitempty"`
	Processes     []Process    `json:"processes,omitempty"`
	ControlGroups []Cgroup     `json:"cgroups,omitempty"`
}

type Filesystem struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type Process struct {
	Name    string `json:"name"`
	PIDFile string `json:"pid_file"`
}

type Cgroup struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func (configuration Config) Validate() error {
	if runtime.GOOS != "linux" {
		return errors.New("Linux metrics require Linux")
	}
	if err := absoluteClean("proc_root", configuration.ProcRoot); err != nil {
		return err
	}
	if configuration.CgroupRoot != "" {
		if err := absoluteClean("cgroup_root", configuration.CgroupRoot); err != nil {
			return err
		}
	}
	if len(configuration.Filesystems) > 32 || len(configuration.Processes) > 32 || len(configuration.ControlGroups) > 32 {
		return errors.New("Linux metric selector limit exceeded")
	}
	names := map[string]bool{}
	for _, filesystem := range configuration.Filesystems {
		if err := selectorName(filesystem.Name, names); err != nil {
			return fmt.Errorf("filesystem: %w", err)
		}
		if err := absoluteClean("filesystem path", filesystem.Path); err != nil {
			return err
		}
	}
	for _, process := range configuration.Processes {
		if err := selectorName(process.Name, names); err != nil {
			return fmt.Errorf("process: %w", err)
		}
		if err := absoluteClean("pid_file", process.PIDFile); err != nil {
			return err
		}
	}
	for _, group := range configuration.ControlGroups {
		if err := selectorName(group.Name, names); err != nil {
			return fmt.Errorf("cgroup: %w", err)
		}
		if configuration.CgroupRoot == "" {
			return errors.New("cgroup_root is required when cgroups are selected")
		}
		if group.Path == "" || filepath.IsAbs(group.Path) || filepath.Clean(group.Path) != group.Path || group.Path == "." || strings.HasPrefix(group.Path, ".."+string(os.PathSeparator)) {
			return errors.New("cgroup path must be a clean relative path below cgroup_root")
		}
	}
	return nil
}

func Collect(configuration Config, now time.Time) ([]model.Observation, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("collection time is required")
	}
	if err := secureDirectory(configuration.ProcRoot); err != nil {
		return nil, errors.New("proc_root is unavailable")
	}
	var observations []model.Observation
	var problems []error
	appendResult := func(result []model.Observation, err error) {
		observations = append(observations, result...)
		if err != nil {
			problems = append(problems, err)
		}
	}
	result, err := collectStat(configuration.ProcRoot, now)
	appendResult(result, err)
	result, err = collectMemory(configuration.ProcRoot, now)
	appendResult(result, err)
	result, err = collectLoad(configuration.ProcRoot, now)
	appendResult(result, err)
	result, err = collectNetwork(configuration.ProcRoot, now)
	appendResult(result, err)
	for _, filesystem := range configuration.Filesystems {
		result, err = collectFilesystem(filesystem, now)
		appendResult(result, err)
	}
	for _, process := range configuration.Processes {
		result, err = collectProcess(configuration.ProcRoot, process, now)
		appendResult(result, err)
	}
	for _, group := range configuration.ControlGroups {
		result, err = collectCgroup(configuration.CgroupRoot, group, now)
		appendResult(result, err)
	}
	if len(observations) > model.MaxRecords {
		return nil, errors.New("Linux metric record limit exceeded")
	}
	return observations, errors.Join(problems...)
}

func collectStat(root string, now time.Time) ([]model.Observation, error) {
	body, err := readBounded(filepath.Join(root, "stat"))
	if err != nil {
		return nil, errors.New("read proc stat")
	}
	var observations []model.Observation
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		states := []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"}
		for index := 1; index < len(fields) && index <= len(states); index++ {
			value, parseErr := strconv.ParseFloat(fields[index], 64)
			if parseErr != nil {
				return nil, errors.New("proc stat contains an invalid CPU counter")
			}
			observations = append(observations, metric(now, "system.cpu.time_ticks", value, "ticks", map[string]string{"state": states[index-1]}))
		}
		break
	}
	uptime, err := readBounded(filepath.Join(root, "uptime"))
	if err == nil {
		fields := strings.Fields(string(uptime))
		if len(fields) > 0 {
			if value, parseErr := strconv.ParseFloat(fields[0], 64); parseErr == nil {
				observations = append(observations, metric(now, "system.uptime", value, "seconds", nil))
			}
		}
	}
	if len(observations) == 0 {
		return nil, errors.New("proc stat contains no aggregate CPU record")
	}
	return observations, nil
}

func collectMemory(root string, now time.Time) ([]model.Observation, error) {
	body, err := readBounded(filepath.Join(root, "meminfo"))
	if err != nil {
		return nil, errors.New("read proc meminfo")
	}
	wanted := map[string]string{"MemTotal": "total", "MemAvailable": "available", "SwapTotal": "swap_total", "SwapFree": "swap_free"}
	var observations []model.Observation
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		state, ok := wanted[strings.TrimSuffix(fields[0], ":")]
		if !ok {
			continue
		}
		value, parseErr := strconv.ParseFloat(fields[1], 64)
		if parseErr != nil {
			return nil, errors.New("proc meminfo contains an invalid value")
		}
		if len(fields) > 2 && fields[2] == "kB" {
			value *= 1024
		}
		observations = append(observations, metric(now, "system.memory", value, "bytes", map[string]string{"state": state}))
	}
	if len(observations) != len(wanted) {
		return observations, errors.New("proc meminfo is missing required values")
	}
	return observations, nil
}

func collectLoad(root string, now time.Time) ([]model.Observation, error) {
	body, err := readBounded(filepath.Join(root, "loadavg"))
	if err != nil {
		return nil, errors.New("read proc loadavg")
	}
	fields := strings.Fields(string(body))
	if len(fields) < 3 {
		return nil, errors.New("proc loadavg is incomplete")
	}
	periods := []string{"1m", "5m", "15m"}
	observations := make([]model.Observation, 0, 3)
	for index := range periods {
		value, parseErr := strconv.ParseFloat(fields[index], 64)
		if parseErr != nil {
			return nil, errors.New("proc loadavg contains an invalid value")
		}
		observations = append(observations, metric(now, "system.load.average", value, "1", map[string]string{"period": periods[index]}))
	}
	return observations, nil
}

func collectNetwork(root string, now time.Time) ([]model.Observation, error) {
	body, err := readBounded(filepath.Join(root, "net", "dev"))
	if err != nil {
		return nil, errors.New("read proc network counters")
	}
	var observations []model.Observation
	for _, line := range strings.Split(string(body), "\n") {
		separator := strings.IndexByte(line, ':')
		if separator < 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		if !safeLabel(name) {
			return nil, errors.New("proc network interface name is invalid")
		}
		fields := strings.Fields(line[separator+1:])
		if len(fields) != 16 {
			return nil, errors.New("proc network counter record is invalid")
		}
		indexes := []struct {
			field int
			name  string
			dir   string
		}{{0, "system.network.bytes", "receive"}, {1, "system.network.packets", "receive"}, {3, "system.network.dropped_packets", "receive"}, {8, "system.network.bytes", "transmit"}, {9, "system.network.packets", "transmit"}, {11, "system.network.dropped_packets", "transmit"}}
		for _, selected := range indexes {
			value, parseErr := strconv.ParseFloat(fields[selected.field], 64)
			if parseErr != nil {
				return nil, errors.New("proc network counter is invalid")
			}
			unit := "1"
			if selected.name == "system.network.bytes" {
				unit = "bytes"
			}
			observations = append(observations, metric(now, selected.name, value, unit, map[string]string{"interface": name, "direction": selected.dir}))
		}
		if len(observations) > 128*6 {
			return nil, errors.New("proc network interface limit exceeded")
		}
	}
	return observations, nil
}

func collectFilesystem(selected Filesystem, now time.Time) ([]model.Observation, error) {
	info, err := os.Lstat(selected.Path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("filesystem %s is unavailable", selected.Name)
	}
	var status syscall.Statfs_t
	if err = syscall.Statfs(selected.Path, &status); err != nil {
		return nil, fmt.Errorf("inspect filesystem %s", selected.Name)
	}
	blockSize := float64(status.Bsize)
	attributes := map[string]string{"filesystem": selected.Name}
	return []model.Observation{
		metric(now, "system.filesystem.bytes", float64(status.Blocks)*blockSize, "bytes", with(attributes, "state", "total")),
		metric(now, "system.filesystem.bytes", float64(status.Bavail)*blockSize, "bytes", with(attributes, "state", "available")),
		metric(now, "system.filesystem.inodes", float64(status.Files), "1", with(attributes, "state", "total")),
		metric(now, "system.filesystem.inodes", float64(status.Ffree), "1", with(attributes, "state", "free")),
	}, nil
}

func collectProcess(procRoot string, selected Process, now time.Time) ([]model.Observation, error) {
	pidBody, err := readBounded(selected.PIDFile)
	if err != nil {
		return []model.Observation{metric(now, "process.up", 0, "1", map[string]string{"process": selected.Name})}, fmt.Errorf("process %s PID is unavailable", selected.Name)
	}
	pidText := strings.TrimSpace(string(pidBody))
	pid, err := strconv.ParseUint(pidText, 10, 31)
	if err != nil || pid == 0 {
		return []model.Observation{metric(now, "process.up", 0, "1", map[string]string{"process": selected.Name})}, fmt.Errorf("process %s PID is invalid", selected.Name)
	}
	stat, err := readBounded(filepath.Join(procRoot, pidText, "stat"))
	if err != nil {
		return []model.Observation{metric(now, "process.up", 0, "1", map[string]string{"process": selected.Name})}, fmt.Errorf("process %s is unavailable", selected.Name)
	}
	closing := strings.LastIndexByte(string(stat), ')')
	if closing < 2 {
		return nil, fmt.Errorf("process %s stat is invalid", selected.Name)
	}
	fields := strings.Fields(string(stat)[closing+1:])
	// fields begin with state (field 3); utime, stime, starttime, vsize, rss
	// are therefore indexes 11, 12, 19, 20, and 21 in this slice.
	if len(fields) < 22 {
		return nil, fmt.Errorf("process %s stat is incomplete", selected.Name)
	}
	values := make([]float64, 5)
	for index, field := range []int{11, 12, 19, 20, 21} {
		values[index], err = strconv.ParseFloat(fields[field], 64)
		if err != nil {
			return nil, fmt.Errorf("process %s stat contains an invalid counter", selected.Name)
		}
	}
	pageSize := float64(os.Getpagesize())
	base := map[string]string{"process": selected.Name}
	observations := []model.Observation{
		metric(now, "process.up", 1, "1", base),
		metric(now, "process.start_time_ticks", values[2], "ticks", base),
		metric(now, "process.cpu.time_ticks", values[0], "ticks", with(base, "state", "user")),
		metric(now, "process.cpu.time_ticks", values[1], "ticks", with(base, "state", "system")),
		metric(now, "process.memory.virtual", values[3], "bytes", base),
		metric(now, "process.memory.resident", values[4]*pageSize, "bytes", base),
	}
	if ioBody, ioErr := readBounded(filepath.Join(procRoot, pidText, "io")); ioErr == nil {
		for _, line := range strings.Split(string(ioBody), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[0] != "read_bytes:" && fields[0] != "write_bytes:" {
				continue
			}
			value, parseErr := strconv.ParseFloat(fields[1], 64)
			if parseErr != nil {
				continue
			}
			direction := strings.TrimSuffix(fields[0], "_bytes:")
			observations = append(observations, metric(now, "process.io.bytes", value, "bytes", with(base, "direction", direction)))
		}
	}
	return observations, nil
}

func collectCgroup(root string, selected Cgroup, now time.Time) ([]model.Observation, error) {
	directory, err := secureRelativeDirectory(root, selected.Path)
	if err != nil {
		return []model.Observation{metric(now, "cgroup.up", 0, "1", map[string]string{"cgroup": selected.Name})}, fmt.Errorf("cgroup %s is unavailable", selected.Name)
	}
	base := map[string]string{"cgroup": selected.Name}
	observations := []model.Observation{metric(now, "cgroup.up", 1, "1", base)}
	for _, scalar := range []struct {
		file, name, unit, state string
	}{{"memory.current", "cgroup.memory", "bytes", "current"}, {"memory.peak", "cgroup.memory", "bytes", "peak"}, {"memory.swap.current", "cgroup.memory", "bytes", "swap"}, {"pids.current", "cgroup.pids", "1", "current"}} {
		body, readErr := readBounded(filepath.Join(directory, scalar.file))
		if readErr != nil {
			continue
		}
		value, parseErr := strconv.ParseFloat(strings.TrimSpace(string(body)), 64)
		if parseErr == nil {
			observations = append(observations, metric(now, scalar.name, value, scalar.unit, with(base, "state", scalar.state)))
		}
	}
	if body, readErr := readBounded(filepath.Join(directory, "cpu.stat")); readErr == nil {
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[0] != "usage_usec" && fields[0] != "user_usec" && fields[0] != "system_usec" {
				continue
			}
			value, parseErr := strconv.ParseFloat(fields[1], 64)
			if parseErr == nil {
				observations = append(observations, metric(now, "cgroup.cpu.time", value, "microseconds", with(base, "state", strings.TrimSuffix(fields[0], "_usec"))))
			}
		}
	}
	if body, readErr := readBounded(filepath.Join(directory, "io.stat")); readErr == nil {
		var readBytes, writeBytes float64
		for _, line := range strings.Split(string(body), "\n") {
			for _, field := range strings.Fields(line) {
				key, text, found := strings.Cut(field, "=")
				if !found || key != "rbytes" && key != "wbytes" {
					continue
				}
				value, parseErr := strconv.ParseFloat(text, 64)
				if parseErr != nil {
					continue
				}
				if key == "rbytes" {
					readBytes += value
				} else {
					writeBytes += value
				}
			}
		}
		observations = append(observations,
			metric(now, "cgroup.io.bytes", readBytes, "bytes", with(base, "direction", "read")),
			metric(now, "cgroup.io.bytes", writeBytes, "bytes", with(base, "direction", "write")),
		)
	}
	return observations, nil
}

func metric(now time.Time, name string, value float64, unit string, attributes map[string]string) model.Observation {
	copied := with(attributes, "unit", unit)
	return model.Observation{Timestamp: now.UTC(), Name: name, Value: &value, Attributes: copied}
}

func with(source map[string]string, key, value string) map[string]string {
	result := make(map[string]string, len(source)+1)
	for existingKey, existingValue := range source {
		result[existingKey] = existingValue
	}
	result[key] = value
	return result
}

func readBounded(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maxSourceBytes {
		return nil, errors.New("metric source is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("metric source changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(bufio.NewReader(file), maxSourceBytes+1))
	if err != nil || len(body) > maxSourceBytes || !utf8.Valid(body) || strings.IndexByte(string(body), 0) >= 0 {
		return nil, errors.New("metric source exceeds accepted bounds")
	}
	return body, nil
}

func secureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a non-symlink directory")
	}
	return nil
}

func secureRelativeDirectory(root, relative string) (string, error) {
	if err := secureDirectory(root); err != nil {
		return "", err
	}
	current := root
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		current = filepath.Join(current, part)
		if err := secureDirectory(current); err != nil {
			return "", err
		}
	}
	return current, nil
}

func absoluteClean(label, value string) error {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("%s must be absolute and clean", label)
	}
	return nil
}

func selectorName(value string, names map[string]bool) error {
	if !safeLabel(value) {
		return errors.New("selector name is invalid")
	}
	if names[value] {
		return errors.New("selector name is duplicated")
	}
	names[value] = true
	return nil
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}
