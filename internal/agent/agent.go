// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gamertan.com/observatory/internal/agentclient"
	"gamertan.com/observatory/internal/agentstate"
	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/edgealert"
	"gamertan.com/observatory/internal/hostmetrics"
	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/spool"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/observatory/internal/tailer"
)

type Sender interface {
	Send(context.Context, model.Batch) (storage.Ack, error)
	SendAlertTransition(context.Context, model.AlertTransition) (storage.SourceAlertTransitionAck, error)
}

type Runner struct {
	configuration config.Agent
	sourceID      string
	stateStore    *agentstate.Store
	state         agentstate.State
	spool         *spool.Spool
	sender        Sender
	agentEpoch    string
}

func Open(configuration config.Agent, credential string, transport http.RoundTripper) (*Runner, error) {
	sourceID, err := sourceIDFromCredential(credential)
	if err != nil {
		return nil, err
	}
	stateStore, state, err := agentstate.Open(configuration.StateFile)
	if err != nil {
		return nil, err
	}
	queue, err := spool.Open(configuration.SpoolDir, configuration.MaxSpoolBytes, configuration.MaxSpoolAge)
	if err != nil {
		return nil, err
	}
	client, err := agentclient.New(configuration.ServerURL, credential, transport)
	if err != nil {
		return nil, err
	}
	return newRunner(configuration, sourceID, stateStore, state, queue, client, agentEpoch(credential))
}

func New(configuration config.Agent, sourceID string, stateStore *agentstate.Store, state agentstate.State, queue *spool.Spool, sender Sender) (*Runner, error) {
	return newRunner(configuration, sourceID, stateStore, state, queue, sender, agentEpoch(sourceID))
}

func newRunner(configuration config.Agent, sourceID string, stateStore *agentstate.Store, state agentstate.State, queue *spool.Spool, sender Sender, epoch string) (*Runner, error) {
	if err := model.ValidateSourceID(sourceID); err != nil || stateStore == nil || queue == nil || sender == nil {
		return nil, errors.New("agent runtime dependencies are invalid")
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if len(epoch) != 32 {
		return nil, errors.New("agent epoch is invalid")
	}
	return &Runner{configuration: configuration, sourceID: sourceID, stateStore: stateStore, state: state, spool: queue, sender: sender, agentEpoch: epoch}, nil
}

func (runner *Runner) RunOnce(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		return errors.New("agent cycle time is required")
	}
	var cycleErrors []error
	if err := runner.recoverCheckpoints(now); err != nil {
		return err
	}
	deliveryFailed := false
	if err := runner.deliver(ctx, now); err != nil {
		cycleErrors = append(cycleErrors, err)
		deliveryFailed = true
	}
	for _, source := range runner.configuration.Sources {
		cursor := runner.state.Streams[source.StreamID]
		if source.Kind == "linux_metrics" {
			observations, collectErr := hostmetrics.Collect(*source.LinuxMetrics, now)
			if len(observations) == 0 {
				if collectErr != nil {
					cycleErrors = append(cycleErrors, fmt.Errorf("collect stream %s: %w", source.StreamID, collectErr))
				}
				continue
			}
			for start := 0; start < len(observations); start += runner.configuration.BatchRecords {
				end := min(start+runner.configuration.BatchRecords, len(observations))
				cursor.Sequence++
				spooled, err := runner.spoolObservations(source.StreamID, cursor, model.SignalMetrics, observations[start:end], now)
				if err != nil {
					if spooled {
						return err
					}
					cycleErrors = append(cycleErrors, fmt.Errorf("spool stream %s: %w", source.StreamID, err))
					break
				}
			}
			if collectErr != nil {
				cycleErrors = append(cycleErrors, fmt.Errorf("collect stream %s: %w", source.StreamID, collectErr))
			}
			continue
		}
		result, err := tailer.Read(source, cursor, runner.configuration.BatchRecords, now)
		if err != nil {
			cycleErrors = append(cycleErrors, fmt.Errorf("collect stream %s: %w", source.StreamID, err))
			continue
		}
		if len(result.Observations) == 0 {
			if result.Cursor != cursor {
				runner.state.Streams[source.StreamID] = result.Cursor
				if err = runner.stateStore.Save(runner.state); err != nil {
					return err
				}
			}
			continue
		}
		result.Cursor.Sequence = cursor.Sequence + 1
		spooled, err := runner.spoolObservations(source.StreamID, result.Cursor, result.Signal, result.Observations, now)
		if err != nil {
			if spooled {
				return err
			}
			cycleErrors = append(cycleErrors, fmt.Errorf("spool stream %s: %w", source.StreamID, err))
			continue
		}
	}
	if !deliveryFailed {
		if err := runner.deliver(ctx, now); err != nil {
			cycleErrors = append(cycleErrors, err)
		}
	}
	return errors.Join(cycleErrors...)
}

func (runner *Runner) spoolObservations(streamID string, cursor agentstate.Cursor, signal model.Signal, observations []model.Observation, now time.Time) (bool, error) {
	batch := model.Batch{Version: model.BatchVersion, SourceID: runner.sourceID, StreamID: streamID, Sequence: cursor.Sequence, ObservedAt: now.UTC(), Signal: signal, Records: observations}
	checkpoint, err := json.Marshal(cursor)
	if err != nil {
		return false, err
	}
	if _, err = runner.spool.PutWithCheckpoint(batch, checkpoint, now); err != nil {
		return false, err
	}
	runner.state.Streams[streamID] = cursor
	return true, runner.stateStore.Save(runner.state)
}

func (runner *Runner) recoverCheckpoints(now time.Time) error {
	entries, err := runner.spool.List(now)
	if err != nil {
		return err
	}
	changed := false
	for _, entry := range entries {
		_, checkpoint, err := runner.spool.ReadWithCheckpoint(entry)
		if err != nil {
			return err
		}
		if len(checkpoint) == 0 {
			return errors.New("pending spool batch lacks a cursor checkpoint")
		}
		cursor, err := decodeCursor(checkpoint)
		if err != nil || cursor.Sequence != entry.Sequence {
			return errors.New("pending spool checkpoint is invalid")
		}
		current := runner.state.Streams[entry.StreamID]
		if cursor.Sequence < current.Sequence {
			continue
		}
		if cursor.Sequence == current.Sequence {
			if cursor != current {
				return errors.New("pending spool checkpoint conflicts with agent state")
			}
			continue
		}
		if cursor.Sequence != current.Sequence+1 {
			return errors.New("pending spool checkpoint has a sequence gap")
		}
		runner.state.Streams[entry.StreamID] = cursor
		changed = true
	}
	if changed {
		return runner.stateStore.Save(runner.state)
	}
	return nil
}

func (runner *Runner) deliver(ctx context.Context, now time.Time) error {
	entries, err := runner.spool.List(now)
	if err != nil {
		return err
	}
	blocked := map[string]bool{}
	var deliveryErrors []error
	for _, entry := range entries {
		if blocked[entry.StreamID] {
			continue
		}
		batch, _, err := runner.spool.ReadWithCheckpoint(entry)
		if err != nil {
			return err
		}
		ack, sendErr := runner.sender.Send(ctx, batch)
		if sendErr != nil {
			blocked[entry.StreamID] = true
			deliveryErrors = append(deliveryErrors, fmt.Errorf("deliver stream %s sequence %d: %w", entry.StreamID, entry.Sequence, sendErr))
			continue
		}
		batchDigest, digestErr := batch.Digest()
		if digestErr != nil || ack.SourceID != batch.SourceID || ack.StreamID != batch.StreamID || ack.Sequence != batch.Sequence || ack.BatchDigest != batchDigest {
			blocked[entry.StreamID] = true
			deliveryErrors = append(deliveryErrors, fmt.Errorf("deliver stream %s sequence %d: acknowledgement does not match exact batch", entry.StreamID, entry.Sequence))
			continue
		}
		transitionFailed := false
		for _, rule := range runner.configuration.AlertRules {
			if rule.StreamID != batch.StreamID {
				continue
			}
			evaluation, evaluationErr := edgealert.Evaluate(rule, batch)
			if evaluationErr != nil {
				blocked[entry.StreamID] = true
				deliveryErrors = append(deliveryErrors, fmt.Errorf("evaluate alert rule %s for stream %s sequence %d: %w", rule.ID, entry.StreamID, entry.Sequence, evaluationErr))
				transitionFailed = true
				break
			}
			transition := model.AlertTransition{Version: model.AlertTransitionVersion, RuleID: rule.ID, RuleRevision: rule.Revision, AgentEpoch: runner.agentEpoch, Sequence: batch.Sequence, StreamID: batch.StreamID, BatchSequence: batch.Sequence, SegmentDigest: ack.Digest, WindowStart: evaluation.WindowStart, WindowEnd: evaluation.WindowEnd, State: evaluation.State, ObservedAt: evaluation.ObservedAt}
			transitionAck, transitionErr := runner.sender.SendAlertTransition(ctx, transition)
			expectedDigest, digestErr := transition.Digest()
			if transitionErr != nil || digestErr != nil || transitionAck.SourceID != batch.SourceID || transitionAck.RuleID != transition.RuleID || transitionAck.RuleRevision != transition.RuleRevision || transitionAck.AgentEpoch != transition.AgentEpoch || transitionAck.Sequence != transition.Sequence || transitionAck.Digest != expectedDigest {
				blocked[entry.StreamID] = true
				if transitionErr == nil {
					transitionErr = errors.New("acknowledgement does not match exact transition")
				}
				deliveryErrors = append(deliveryErrors, fmt.Errorf("deliver alert rule %s for stream %s sequence %d: %w", rule.ID, entry.StreamID, entry.Sequence, transitionErr))
				transitionFailed = true
				break
			}
		}
		if transitionFailed {
			continue
		}
		if err = runner.spool.Acknowledge(entry, entry.Digest); err != nil {
			return err
		}
	}
	return errors.Join(deliveryErrors...)
}

func agentEpoch(sourceID string) string {
	digest := sha256.Sum256([]byte("observatory-agent-epoch-v1\x00" + sourceID))
	return hex.EncodeToString(digest[:16])
}

func decodeCursor(body []byte) (agentstate.Cursor, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var cursor agentstate.Cursor
	if err := decoder.Decode(&cursor); err != nil {
		return agentstate.Cursor{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return agentstate.Cursor{}, errors.New("cursor checkpoint has trailing data")
	}
	if cursor.Offset < 0 || (cursor.Device == 0) != (cursor.Inode == 0) || cursor.Sequence == 0 {
		return agentstate.Cursor{}, errors.New("cursor checkpoint is invalid")
	}
	return cursor, nil
}

func sourceIDFromCredential(credential string) (string, error) {
	if !strings.HasPrefix(credential, "obs1.") || strings.ContainsAny(credential, " \t\r\n") {
		return "", errors.New("source credential is invalid")
	}
	remainder := strings.TrimPrefix(credential, "obs1.")
	separator := strings.LastIndexByte(remainder, '.')
	if separator < 1 || separator == len(remainder)-1 {
		return "", errors.New("source credential is invalid")
	}
	sourceID := remainder[:separator]
	if err := model.ValidateSourceID(sourceID); err != nil {
		return "", errors.New("source credential is invalid")
	}
	return sourceID, nil
}
