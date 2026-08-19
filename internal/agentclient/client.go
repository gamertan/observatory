// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

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
	"net/url"
	"strings"
	"time"

	"gamertan.com/observatory/internal/model"
	"gamertan.com/observatory/internal/nativeprotocol"
	"gamertan.com/observatory/internal/storage"
)

type Client struct {
	endpoint      string
	alertEndpoint string
	credential    string
	sourceID      string
	http          *http.Client
}

type EnrollmentResult struct {
	SourceID   string `json:"source_id"`
	Credential string `json:"credential"`
}

func Enroll(ctx context.Context, serverURL, enrollmentToken string, transport http.RoundTripper) (EnrollmentResult, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return EnrollmentResult{}, errors.New("server URL must be an absolute HTTPS origin")
	}
	if len(enrollmentToken) != len("obse1.")+64 || !strings.HasPrefix(enrollmentToken, "obse1.") || strings.ContainsAny(enrollmentToken, " \t\r\n") {
		return EnrollmentResult{}, errors.New("invalid enrollment token")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(serverURL, "/")+"/api/v1/agent/enroll", http.NoBody)
	if err != nil {
		return EnrollmentResult{}, errors.New("create enrollment request")
	}
	request.Header.Set("Authorization", "Bearer "+enrollmentToken)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return EnrollmentResult{}, errors.New("enrollment request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return EnrollmentResult{}, fmt.Errorf("enrollment returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var result EnrollmentResult
	if err = decoder.Decode(&result); err != nil {
		return EnrollmentResult{}, errors.New("invalid enrollment response")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return EnrollmentResult{}, errors.New("enrollment response has trailing data")
	}
	if err = validateCredential(result.SourceID, result.Credential); err != nil {
		return EnrollmentResult{}, err
	}
	return result, nil
}

func RevokeSource(ctx context.Context, serverURL, credential string, transport http.RoundTripper) error {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server URL must be an absolute HTTPS origin")
	}
	if len(credential) < 48 || len(credential) > 512 || !strings.HasPrefix(credential, "obs1.") || strings.ContainsAny(credential, " \t\r\n") {
		return errors.New("invalid source credential")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimSuffix(serverURL, "/")+"/api/v1/agent/source", http.NoBody)
	if err != nil {
		return errors.New("create source revocation request")
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("source revocation request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("source revocation returned HTTP %d", response.StatusCode)
	}
	return nil
}

func New(serverURL, credential string, transport http.RoundTripper) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("server URL must be an absolute HTTPS origin")
	}
	sourceID, credentialErr := credentialSourceID(credential)
	if credentialErr != nil {
		return nil, errors.New("invalid source credential")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	base := strings.TrimSuffix(serverURL, "/")
	return &Client{endpoint: base + "/api/v2/ingest/native", alertEndpoint: base + "/api/v1/agent/alert-transition", credential: credential, sourceID: sourceID, http: httpClient}, nil
}

func (c *Client) SendAlertTransition(ctx context.Context, transition model.AlertTransition) (storage.SourceAlertTransitionAck, error) {
	b, err := json.Marshal(transition)
	if err != nil {
		return storage.SourceAlertTransitionAck{}, errors.New("encode source alert transition")
	}
	expectedDigest, err := transition.Digest()
	if err != nil {
		return storage.SourceAlertTransitionAck{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.alertEndpoint, bytes.NewReader(b))
	if err != nil {
		return storage.SourceAlertTransitionAck{}, errors.New("create source alert transition request")
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return storage.SourceAlertTransitionAck{}, errors.New("source alert transition request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return storage.SourceAlertTransitionAck{}, fmt.Errorf("source alert transition returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var ack storage.SourceAlertTransitionAck
	if err = decoder.Decode(&ack); err != nil {
		return storage.SourceAlertTransitionAck{}, errors.New("invalid source alert transition acknowledgement")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return storage.SourceAlertTransitionAck{}, errors.New("source alert transition acknowledgement has trailing data")
	}
	if ack.SourceID != c.sourceID || ack.RuleID != transition.RuleID || ack.RuleRevision != transition.RuleRevision || ack.AgentEpoch != transition.AgentEpoch || ack.Sequence != transition.Sequence || ack.Digest != expectedDigest {
		return storage.SourceAlertTransitionAck{}, errors.New("source alert transition acknowledgement does not match transition")
	}
	return ack, nil
}

func credentialSourceID(credential string) (string, error) {
	if len(credential) < 48 || len(credential) > 512 || !strings.HasPrefix(credential, "obs1.") || strings.ContainsAny(credential, " \t\r\n") {
		return "", errors.New("invalid source credential")
	}
	remainder := strings.TrimPrefix(credential, "obs1.")
	separator := strings.LastIndexByte(remainder, '.')
	if separator < 1 || separator == len(remainder)-1 {
		return "", errors.New("invalid source credential")
	}
	sourceID := remainder[:separator]
	if model.ValidateSourceID(sourceID) != nil {
		return "", errors.New("invalid source credential")
	}
	return sourceID, nil
}

func validateCredential(sourceID, credential string) error {
	if model.ValidateSourceID(sourceID) != nil || len(credential) < 48 || len(credential) > 512 || !strings.HasPrefix(credential, "obs1."+sourceID+".") || strings.ContainsAny(credential, " \t\r\n") {
		return errors.New("invalid source credential")
	}
	return nil
}

func (c *Client) Send(ctx context.Context, batch model.Batch) (storage.Ack, error) {
	b, err := json.Marshal(batch)
	if err != nil {
		return storage.Ack{}, errors.New("encode native batch")
	}
	envelope, err := batch.Envelope(b)
	if err != nil {
		return storage.Ack{}, errors.New("encode native batch envelope")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(b))
	if err != nil {
		return storage.Ack{}, errors.New("create ingestion request")
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	nativeprotocol.SetHeaders(request.Header, envelope)
	response, err := c.http.Do(request)
	if err != nil {
		return storage.Ack{}, errors.New("ingestion request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return storage.Ack{}, fmt.Errorf("ingestion returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var ack storage.Ack
	if err := decoder.Decode(&ack); err != nil {
		return storage.Ack{}, errors.New("invalid ingestion acknowledgement")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return storage.Ack{}, errors.New("ingestion acknowledgement has trailing data")
	}
	decodedDigest, digestErr := hex.DecodeString(ack.Digest)
	decodedBatchDigest, batchDigestErr := hex.DecodeString(ack.BatchDigest)
	if ack.SourceID != batch.SourceID || ack.StreamID != batch.StreamID || ack.Sequence != batch.Sequence || digestErr != nil || len(decodedDigest) != sha256.Size || batchDigestErr != nil || len(decodedBatchDigest) != sha256.Size || ack.BatchDigest != envelope.BatchDigest {
		return storage.Ack{}, errors.New("ingestion acknowledgement does not match batch")
	}
	return ack, nil
}
