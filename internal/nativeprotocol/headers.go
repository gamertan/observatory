// SPDX-License-Identifier: AGPL-3.0-only

package nativeprotocol

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"gamertan.com/observatory/internal/model"
)

const (
	VersionHeader       = "Observatory-Batch-Version"
	StreamHeader        = "Observatory-Stream-ID"
	SequenceHeader      = "Observatory-Sequence"
	SignalHeader        = "Observatory-Signal"
	WireDigestHeader    = "Observatory-Wire-SHA256"
	BatchDigestHeader   = "Observatory-Batch-SHA256"
	RecordCountHeader   = "Observatory-Record-Count"
	EncodedBytesHeader  = "Observatory-Encoded-Bytes"
	FirstObservedHeader = "Observatory-First-Observed-At"
	LastObservedHeader  = "Observatory-Last-Observed-At"
)

var envelopeHeaders = []string{
	VersionHeader, StreamHeader, SequenceHeader, SignalHeader,
	WireDigestHeader, BatchDigestHeader, RecordCountHeader,
	EncodedBytesHeader, FirstObservedHeader, LastObservedHeader,
}

func SetHeaders(header http.Header, envelope model.BatchEnvelope) {
	header.Set(VersionHeader, strconv.Itoa(envelope.Version))
	header.Set(StreamHeader, envelope.StreamID)
	header.Set(SequenceHeader, strconv.FormatUint(envelope.Sequence, 10))
	header.Set(SignalHeader, string(envelope.Signal))
	header.Set(WireDigestHeader, envelope.WireDigest)
	header.Set(BatchDigestHeader, envelope.BatchDigest)
	header.Set(RecordCountHeader, strconv.Itoa(envelope.RecordCount))
	header.Set(EncodedBytesHeader, strconv.FormatInt(envelope.EncodedBytes, 10))
	header.Set(FirstObservedHeader, envelope.FirstObservedAt.UTC().Format(time.RFC3339Nano))
	header.Set(LastObservedHeader, envelope.LastObservedAt.UTC().Format(time.RFC3339Nano))
}

func ParseHeaders(header http.Header, maxEncodedBytes int64) (model.BatchEnvelope, error) {
	values := make(map[string]string, len(envelopeHeaders))
	for _, name := range envelopeHeaders {
		items := header.Values(name)
		if len(items) != 1 || items[0] == "" {
			return model.BatchEnvelope{}, errors.New("native batch envelope headers are incomplete")
		}
		values[name] = items[0]
	}
	version, versionErr := strconv.Atoi(values[VersionHeader])
	sequence, sequenceErr := strconv.ParseUint(values[SequenceHeader], 10, 64)
	recordCount, recordErr := strconv.Atoi(values[RecordCountHeader])
	encodedBytes, bytesErr := strconv.ParseInt(values[EncodedBytesHeader], 10, 64)
	first, firstErr := time.Parse(time.RFC3339Nano, values[FirstObservedHeader])
	last, lastErr := time.Parse(time.RFC3339Nano, values[LastObservedHeader])
	if versionErr != nil || sequenceErr != nil || recordErr != nil || bytesErr != nil || firstErr != nil || lastErr != nil {
		return model.BatchEnvelope{}, errors.New("native batch envelope headers are invalid")
	}
	envelope := model.BatchEnvelope{
		Version: version, StreamID: values[StreamHeader], Sequence: sequence,
		Signal: model.Signal(values[SignalHeader]), WireDigest: values[WireDigestHeader],
		BatchDigest: values[BatchDigestHeader], RecordCount: recordCount,
		EncodedBytes: encodedBytes, FirstObservedAt: first.UTC(), LastObservedAt: last.UTC(),
	}
	if err := envelope.Validate(maxEncodedBytes); err != nil {
		return model.BatchEnvelope{}, errors.New("native batch envelope headers are invalid")
	}
	return envelope, nil
}
