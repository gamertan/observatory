// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gamertan.com/observatory/internal/hostmetrics"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/query"
)

const SchemaVersion = 1

type Server struct {
	Schema              int           `json:"schema"`
	Listen              string        `json:"listen"`
	PublicURL           string        `json:"public_url"`
	DataDir             string        `json:"data_dir"`
	MaxBodyBytes        int64         `json:"max_body_bytes"`
	MaxConcurrentIngest int           `json:"max_concurrent_ingest,omitempty"`
	SessionLifetimeText string        `json:"session_lifetime"`
	SessionLifetime     time.Duration `json:"-"`
	Query               QueryLimits   `json:"query"`
	Retention           Retention     `json:"retention"`
	WebPush             *WebPush      `json:"web_push,omitempty"`
}

type WebPush struct {
	PrivateKeyFile string        `json:"private_key_file"`
	Subject        string        `json:"subject"`
	QueueCapacity  int           `json:"queue_capacity"`
	RequestTimeout string        `json:"request_timeout"`
	Timeout        time.Duration `json:"-"`
	PrivateKey     []byte        `json:"-"`
}

type QueryLimits struct {
	MaxDuration     time.Duration `json:"-"`
	MaxDurationText string        `json:"max_duration"`
	MaxRows         int           `json:"max_rows"`
	MaxScannedBytes int64         `json:"max_scanned_bytes"`
	MaxMemoryBytes  int64         `json:"max_memory_bytes"`
}

type Retention struct {
	RawLogsDays       int  `json:"raw_logs_days"`
	RawTracesDays     int  `json:"raw_traces_days"`
	RawMetricsDays    int  `json:"raw_metrics_days"`
	ColdRawDays       int  `json:"cold_raw_days"`
	DeleteColdRaw     bool `json:"delete_cold_raw"`
	MetricRollupsDays int  `json:"metric_rollups_days"`
	EvidenceDays      int  `json:"evidence_days"`
}

type FilePolicy struct {
	RequireRoot                bool
	SystemdCredentialDirectory string
}

func SystemdCredentialPolicy() (FilePolicy, error) {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		return FilePolicy{}, errors.New("CREDENTIALS_DIRECTORY is not set")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return FilePolicy{}, errors.New("CREDENTIALS_DIRECTORY must be an absolute clean path")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return FilePolicy{}, fmt.Errorf("inspect CREDENTIALS_DIRECTORY: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return FilePolicy{}, errors.New("CREDENTIALS_DIRECTORY must be a non-symlink directory")
	}
	return FilePolicy{SystemdCredentialDirectory: directory}, nil
}

type Agent struct {
	Schema          int              `json:"schema"`
	ServerURL       string           `json:"server_url"`
	CredentialFile  string           `json:"credential_file"`
	SpoolDir        string           `json:"spool_dir"`
	StateFile       string           `json:"state_file"`
	MaxSpoolBytes   int64            `json:"max_spool_bytes"`
	MaxSpoolAgeText string           `json:"max_spool_age"`
	MaxSpoolAge     time.Duration    `json:"-"`
	BatchRecords    int              `json:"batch_records"`
	FlushInterval   string           `json:"flush_interval"`
	FlushEvery      time.Duration    `json:"-"`
	Sources         []AgentSource    `json:"sources"`
	AlertRules      []AgentAlertRule `json:"alert_rules,omitempty"`
}

type AgentSource struct {
	Kind            string              `json:"kind"`
	Path            string              `json:"path,omitempty"`
	StreamID        string              `json:"stream_id"`
	SensitiveFields []string            `json:"sensitive_fields,omitempty"`
	LinuxMetrics    *hostmetrics.Config `json:"linux_metrics,omitempty"`
}

type AgentAlertRule struct {
	Version        int       `json:"version"`
	ID             string    `json:"id"`
	Revision       int       `json:"revision"`
	StreamID       string    `json:"stream_id"`
	Query          string    `json:"query"`
	MinimumMatches int       `json:"minimum_matches"`
	AST            query.AST `json:"-"`
}

func LoadServer(path string, policy FilePolicy) (Server, error) {
	var cfg Server
	if err := loadStrict(path, policy, &cfg); err != nil {
		return Server{}, err
	}
	if cfg.Schema != SchemaVersion {
		return Server{}, fmt.Errorf("unsupported server configuration schema %d", cfg.Schema)
	}
	if cfg.Listen == "" {
		return Server{}, errors.New("listen is required")
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Server{}, errors.New("public_url must be an absolute HTTPS origin")
	}
	if !filepath.IsAbs(cfg.DataDir) || filepath.Clean(cfg.DataDir) != cfg.DataDir {
		return Server{}, errors.New("data_dir must be an absolute clean path")
	}
	if cfg.MaxBodyBytes < 1024 || cfg.MaxBodyBytes > 64<<20 {
		return Server{}, errors.New("max_body_bytes must be between 1024 and 67108864")
	}
	if cfg.MaxConcurrentIngest == 0 {
		cfg.MaxConcurrentIngest = 8
	}
	if cfg.MaxConcurrentIngest < 1 || cfg.MaxConcurrentIngest > 64 {
		return Server{}, errors.New("max_concurrent_ingest must be between 1 and 64")
	}
	sessionLifetime, err := time.ParseDuration(cfg.SessionLifetimeText)
	if err != nil || sessionLifetime < 5*time.Minute || sessionLifetime > 30*24*time.Hour {
		return Server{}, errors.New("session_lifetime must be between 5m and 720h")
	}
	cfg.SessionLifetime = sessionLifetime
	if cfg.Query.MaxRows < 1 || cfg.Query.MaxRows > 100_000 {
		return Server{}, errors.New("query.max_rows must be between 1 and 100000")
	}
	if cfg.Query.MaxScannedBytes < 1 || cfg.Query.MaxMemoryBytes < 1 {
		return Server{}, errors.New("query byte limits must be positive")
	}
	d, err := time.ParseDuration(cfg.Query.MaxDurationText)
	if err != nil || d < time.Millisecond || d > time.Minute {
		return Server{}, errors.New("query.max_duration must be between 1ms and 1m")
	}
	cfg.Query.MaxDuration = d
	if err := cfg.Retention.validate(); err != nil {
		return Server{}, err
	}
	if cfg.WebPush != nil {
		if !filepath.IsAbs(cfg.WebPush.PrivateKeyFile) || filepath.Clean(cfg.WebPush.PrivateKeyFile) != cfg.WebPush.PrivateKeyFile {
			return Server{}, errors.New("web_push.private_key_file must be an absolute clean path")
		}
		if err = validateWebPushSubject(cfg.WebPush.Subject); err != nil {
			return Server{}, err
		}
		if cfg.WebPush.QueueCapacity < 1 || cfg.WebPush.QueueCapacity > 1024 {
			return Server{}, errors.New("web_push.queue_capacity must be between 1 and 1024")
		}
		cfg.WebPush.Timeout, err = time.ParseDuration(cfg.WebPush.RequestTimeout)
		if err != nil || cfg.WebPush.Timeout < time.Second || cfg.WebPush.Timeout > 30*time.Second {
			return Server{}, errors.New("web_push.request_timeout must be between 1s and 30s")
		}
		cfg.WebPush.PrivateKey, err = LoadWebPushPrivateKey(cfg.WebPush.PrivateKeyFile, policy)
		if err != nil {
			return Server{}, err
		}
	}
	return cfg, nil
}

func LoadAgent(path string, policy FilePolicy) (Agent, error) {
	var cfg Agent
	if err := loadStrict(path, policy, &cfg); err != nil {
		return Agent{}, err
	}
	if cfg.Schema != SchemaVersion {
		return Agent{}, fmt.Errorf("unsupported agent configuration schema %d", cfg.Schema)
	}
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Agent{}, errors.New("server_url must be an absolute HTTPS origin")
	}
	for label, path := range map[string]string{"credential_file": cfg.CredentialFile, "spool_dir": cfg.SpoolDir, "state_file": cfg.StateFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return Agent{}, fmt.Errorf("%s must be an absolute clean path", label)
		}
	}
	if cfg.SpoolDir == cfg.StateFile || !strings.HasPrefix(cfg.StateFile, cfg.SpoolDir+string(os.PathSeparator)) {
		return Agent{}, errors.New("state_file must be below spool_dir")
	}
	if cfg.MaxSpoolBytes < 1<<20 || cfg.MaxSpoolBytes > 5<<30 {
		return Agent{}, errors.New("max_spool_bytes must be between 1 MiB and 5 GiB")
	}
	age, err := time.ParseDuration(cfg.MaxSpoolAgeText)
	if err != nil || age < time.Hour || age > 72*time.Hour {
		return Agent{}, errors.New("max_spool_age must be between 1h and 72h")
	}
	cfg.MaxSpoolAge = age
	flush, err := time.ParseDuration(cfg.FlushInterval)
	if err != nil || flush < 100*time.Millisecond || flush > time.Minute {
		return Agent{}, errors.New("flush_interval must be between 100ms and 1m")
	}
	cfg.FlushEvery = flush
	if cfg.BatchRecords < 1 || cfg.BatchRecords > model.MaxRecords {
		return Agent{}, fmt.Errorf("batch_records must be between 1 and %d", model.MaxRecords)
	}
	if len(cfg.Sources) < 1 || len(cfg.Sources) > 64 {
		return Agent{}, errors.New("sources must contain between 1 and 64 entries")
	}
	streams := map[string]bool{}
	for index, source := range cfg.Sources {
		switch source.Kind {
		case "caddy_json", "requestlog_jsonl", "tend_events_jsonl":
			if source.LinuxMetrics != nil {
				return Agent{}, fmt.Errorf("sources[%d].linux_metrics is only valid for linux_metrics", index)
			}
			if !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path {
				return Agent{}, fmt.Errorf("sources[%d].path must be absolute and clean", index)
			}
		case "linux_metrics":
			if source.Path != "" || source.LinuxMetrics == nil {
				return Agent{}, fmt.Errorf("sources[%d] requires linux_metrics and no path", index)
			}
			if err := source.LinuxMetrics.Validate(); err != nil {
				return Agent{}, fmt.Errorf("sources[%d]: %w", index, err)
			}
		default:
			return Agent{}, fmt.Errorf("sources[%d].kind is unsupported", index)
		}
		allowedSensitive := map[string]bool{}
		switch source.Kind {
		case "caddy_json":
			for _, name := range []string{"client_ip", "query", "referrer", "user_agent"} {
				allowedSensitive[name] = true
			}
		case "requestlog_jsonl":
			for _, name := range []string{"client_ip", "query", "referrer", "session_id", "user_agent"} {
				allowedSensitive[name] = true
			}
		}
		selectedSensitive := map[string]bool{}
		for _, name := range source.SensitiveFields {
			if !allowedSensitive[name] {
				return Agent{}, fmt.Errorf("sources[%d].sensitive_fields contains unsupported field %q", index, name)
			}
			if selectedSensitive[name] {
				return Agent{}, fmt.Errorf("sources[%d].sensitive_fields duplicates %q", index, name)
			}
			selectedSensitive[name] = true
		}
		if err := model.ValidateStreamID(source.StreamID); err != nil {
			return Agent{}, fmt.Errorf("sources[%d]: %w", index, err)
		}
		if streams[source.StreamID] {
			return Agent{}, fmt.Errorf("sources[%d].stream_id is duplicated", index)
		}
		streams[source.StreamID] = true
	}
	rules := map[string]bool{}
	for index := range cfg.AlertRules {
		rule := &cfg.AlertRules[index]
		if rule.Version != 1 || model.ValidateSourceID(rule.ID) != nil || rule.Revision < 1 || rule.Revision > 1_000_000 || !streams[rule.StreamID] || rule.MinimumMatches < 1 || rule.MinimumMatches > model.MaxRecords || rules[rule.ID] {
			return Agent{}, fmt.Errorf("alert_rules[%d] identity is invalid", index)
		}
		var sourceKind string
		for _, source := range cfg.Sources {
			if source.StreamID == rule.StreamID {
				sourceKind = source.Kind
				break
			}
		}
		if sourceKind != "caddy_json" && sourceKind != "requestlog_jsonl" {
			return Agent{}, fmt.Errorf("alert_rules[%d] requires a log stream", index)
		}
		rule.AST, err = query.Parse(rule.Query, model.MaxRecords)
		if err != nil || rule.AST.Signal != model.SignalLogs || len(rule.AST.Filters) == 0 || rule.AST.Summary != nil || rule.AST.Sort != nil || rule.AST.Window != 0 || rule.AST.Limit < rule.MinimumMatches {
			return Agent{}, fmt.Errorf("alert_rules[%d] query must be a bounded logs filter without sort, summary, or window", index)
		}
		for _, filter := range rule.AST.Filters {
			switch query.CanonicalField(filter.Field) {
			case "project.id", "environment.id", "service.id", "source.id", "stream.id":
				return Agent{}, fmt.Errorf("alert_rules[%d] cannot filter server-derived scope", index)
			}
		}
		rules[rule.ID] = true
	}
	return cfg, nil
}

func LoadCredential(path string, policy FilePolicy) (string, error) {
	var holder struct {
		Credential string `json:"credential"`
	}
	if err := loadStrict(path, policy, &holder); err != nil {
		return "", err
	}
	if len(holder.Credential) < 48 || len(holder.Credential) > 512 || !strings.HasPrefix(holder.Credential, "obs1.") || strings.ContainsAny(holder.Credential, " \t\r\n") {
		return "", errors.New("credential file contains an invalid source credential")
	}
	return holder.Credential, nil
}

func LoadEnrollmentToken(path string, policy FilePolicy) (string, error) {
	var holder struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := loadStrict(path, policy, &holder); err != nil {
		return "", err
	}
	if len(holder.EnrollmentToken) != len("obse1.")+64 || !strings.HasPrefix(holder.EnrollmentToken, "obse1.") || strings.ContainsAny(holder.EnrollmentToken, " \t\r\n") {
		return "", errors.New("enrollment file contains an invalid token")
	}
	return holder.EnrollmentToken, nil
}

func WriteEnrollmentToken(path, token string) error {
	if len(token) != len("obse1.")+64 || !strings.HasPrefix(token, "obse1.") || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("invalid enrollment token")
	}
	return writePrivateJSON(path, struct {
		EnrollmentToken string `json:"enrollment_token"`
	}{token})
}

func WriteCredential(path, credential string) error {
	if len(credential) < 48 || len(credential) > 512 || !strings.HasPrefix(credential, "obs1.") || strings.ContainsAny(credential, " \t\r\n") {
		return errors.New("invalid source credential")
	}
	return writePrivateJSON(path, struct {
		Credential string `json:"credential"`
	}{credential})
}

func LoadWebPushPrivateKey(path string, policy FilePolicy) ([]byte, error) {
	var holder struct {
		PrivateKey string `json:"private_key"`
	}
	if err := loadStrict(path, policy, &holder); err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(holder.PrivateKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("web push private key file is invalid")
	}
	if _, err = ecdh.P256().NewPrivateKey(key); err != nil {
		return nil, errors.New("web push private key file is invalid")
	}
	return key, nil
}

func WriteWebPushPrivateKey(path string, key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid web push private key")
	}
	if _, err := ecdh.P256().NewPrivateKey(key); err != nil {
		return errors.New("invalid web push private key")
	}
	return writePrivateJSON(path, struct {
		PrivateKey string `json:"private_key"`
	}{base64.RawURLEncoding.EncodeToString(key)})
}

func writePrivateJSON(path string, value any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("secret output path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret output directory must be an existing non-symlink directory")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create secret output: %w", err)
	}
	body, marshalErr := json.Marshal(value)
	if marshalErr == nil {
		body = append(body, '\n')
		_, marshalErr = file.Write(body)
	}
	if marshalErr == nil {
		marshalErr = file.Sync()
	}
	if closeErr := file.Close(); marshalErr == nil {
		marshalErr = closeErr
	}
	if marshalErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write secret output: %w", marshalErr)
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (r Retention) validate() error {
	values := []int{r.RawLogsDays, r.RawTracesDays, r.RawMetricsDays, r.ColdRawDays, r.MetricRollupsDays, r.EvidenceDays}
	for _, days := range values {
		if days < 1 || days > 3650 {
			return errors.New("retention values must be between 1 and 3650 days")
		}
	}
	if r.MetricRollupsDays < r.RawMetricsDays {
		return errors.New("metric rollup retention cannot be shorter than raw metric retention")
	}
	if r.ColdRawDays < r.RawLogsDays || r.ColdRawDays < r.RawTracesDays || r.ColdRawDays < r.RawMetricsDays || r.ColdRawDays < r.EvidenceDays {
		return errors.New("cold raw retention cannot be shorter than a hot raw or evidence retention window")
	}
	return nil
}

func validateWebPushSubject(subject string) error {
	if len(subject) < 8 || len(subject) > 512 || strings.ContainsAny(subject, " \t\r\n") {
		return errors.New("web_push.subject is invalid")
	}
	parsed, err := url.Parse(subject)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("web_push.subject is invalid")
	}
	if parsed.Scheme == "mailto" && parsed.Opaque != "" && strings.Contains(parsed.Opaque, "@") {
		return nil
	}
	if parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil {
		return nil
	}
	return errors.New("web_push.subject must be a mailto address or HTTPS URL")
}

func loadStrict(path string, policy FilePolicy, out any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("configuration path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect configuration: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("configuration must be a regular non-symlink file")
	}
	if policy.SystemdCredentialDirectory != "" {
		if filepath.Dir(path) != policy.SystemdCredentialDirectory {
			return errors.New("runtime credential must be a direct child of CREDENTIALS_DIRECTORY")
		}
		mode := info.Mode().Perm()
		if mode != 0o400 && mode != 0o440 && mode != 0o600 {
			return fmt.Errorf("runtime credential mode must be 0400, 0440, or 0600, got %04o", mode)
		}
		if runtime.GOOS != "linux" {
			return errors.New("systemd credential validation is supported only on Linux")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("runtime credential must be owned by root or the service user")
		}
	} else if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("configuration mode must be 0600, got %04o", info.Mode().Perm())
	}
	if policy.RequireRoot {
		if runtime.GOOS != "linux" {
			return errors.New("root ownership validation is supported only on Linux")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("configuration must be owned by root")
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("configuration must contain exactly one JSON value")
	}
	return nil
}
