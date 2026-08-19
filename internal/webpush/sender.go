// SPDX-License-Identifier: AGPL-3.0-only

// Package webpush implements the deliberately narrow Web Push boundary used
// by Observatory. It accepts only validated HTTPS push-service endpoints and
// encrypts one fixed, generic notification payload.
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	GenericMessage       = "Gamertan Observatory needs your attention."
	maxEndpointBytes     = 2048
	maxResponseBodyBytes = 4096
)

var ErrSubscriptionGone = errors.New("web push subscription is gone")

type Subscription struct {
	Endpoint string
	P256DH   []byte
	Auth     []byte
}

type Options struct {
	PrivateKey []byte
	Subject    string
	Timeout    time.Duration
	Client     *http.Client
	Now        func() time.Time
	Random     io.Reader
}

type Sender struct {
	private *ecdh.PrivateKey
	subject string
	timeout time.Duration
	client  *http.Client
	now     func() time.Time
	random  io.Reader
}

func New(options Options) (*Sender, error) {
	private, err := ecdh.P256().NewPrivateKey(options.PrivateKey)
	if err != nil {
		return nil, errors.New("web push private key is invalid")
	}
	if err = validateSubject(options.Subject); err != nil {
		return nil, err
	}
	if options.Timeout < time.Second || options.Timeout > 30*time.Second {
		return nil, errors.New("web push timeout must be between 1s and 30s")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Client == nil {
		options.Client = safeClient(options.Timeout)
	}
	return &Sender{private: private, subject: options.Subject, timeout: options.Timeout, client: options.Client, now: options.Now, random: options.Random}, nil
}

func (s *Sender) PublicKey() string {
	return base64.RawURLEncoding.EncodeToString(s.private.PublicKey().Bytes())
}

func (s *Sender) Send(ctx context.Context, subscription Subscription) error {
	endpoint, err := ValidateEndpoint(subscription.Endpoint)
	if err != nil {
		return err
	}
	body, _, err := encrypt([]byte(GenericMessage), subscription, s.random)
	if err != nil {
		return err
	}
	jwt, err := s.vapid(endpoint, s.now(), s.random)
	if err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("create web push request")
	}
	request.Header.Set("Authorization", "vapid t="+jwt+", k="+s.PublicKey())
	request.Header.Set("Content-Encoding", "aes128gcm")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("TTL", "300")
	request.Header.Set("Urgency", "high")
	response, err := s.client.Do(request)
	if err != nil {
		return errors.New("deliver web push notification")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBodyBytes))
	if response.StatusCode == http.StatusGone || response.StatusCode == http.StatusNotFound {
		return ErrSubscriptionGone
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("web push service returned status %d", response.StatusCode)
	}
	return nil
}

func ValidateEndpoint(raw string) (*url.URL, error) {
	if len(raw) < len("https://a.b/x") || len(raw) > maxEndpointBytes || !strings.HasPrefix(raw, "https://") {
		return nil, errors.New("web push endpoint must be a bounded HTTPS URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("web push endpoint is invalid")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return nil, errors.New("web push endpoint port is not permitted")
	}
	host := parsed.Hostname()
	if net.ParseIP(host) != nil || !validDNSName(host) {
		return nil, errors.New("web push endpoint host is invalid")
	}
	if parsed.Path == "" || parsed.Path[0] != '/' {
		return nil, errors.New("web push endpoint path is invalid")
	}
	return parsed, nil
}

func validateSubject(subject string) error {
	if len(subject) < 8 || len(subject) > 512 || strings.ContainsAny(subject, "\r\n\t ") {
		return errors.New("web push subject is invalid")
	}
	parsed, err := url.Parse(subject)
	if err != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return errors.New("web push subject is invalid")
	}
	if parsed.Scheme == "mailto" && parsed.Opaque != "" && strings.Contains(parsed.Opaque, "@") {
		return nil
	}
	if parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil {
		return nil
	}
	return errors.New("web push subject must be a mailto address or HTTPS URL")
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || strings.EqualFold(host, "localhost") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character > 127 || !(character == '-' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
				return false
			}
		}
	}
	return true
}

func safeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" || !validDNSName(host) {
				return nil, errors.New("web push dial target is invalid")
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(addresses) == 0 {
				return nil, errors.New("resolve web push endpoint")
			}
			var last error
			for _, candidate := range addresses {
				if !publicIP(candidate.IP) {
					return nil, errors.New("web push endpoint resolved to a non-public address")
				}
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				last = dialErr
			}
			if last != nil {
				return nil, errors.New("connect to web push endpoint")
			}
			return nil, errors.New("web push endpoint has no usable address")
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("web push redirects are disabled")
	}}
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range deniedPushPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var deniedPushPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func encrypt(payload []byte, subscription Subscription, random io.Reader) ([]byte, []byte, error) {
	if len(payload) == 0 || len(payload) > 2048 || len(subscription.P256DH) != 65 || subscription.P256DH[0] != 4 || len(subscription.Auth) != 16 {
		return nil, nil, errors.New("web push subscription keys are invalid")
	}
	serverPrivate, err := ecdh.P256().GenerateKey(random)
	if err != nil {
		return nil, nil, errors.New("generate web push content key")
	}
	salt := make([]byte, 16)
	if _, err = io.ReadFull(random, salt); err != nil {
		return nil, nil, errors.New("generate web push salt")
	}
	return encryptWithMaterial(payload, subscription, serverPrivate, salt)
}

func encryptWithMaterial(payload []byte, subscription Subscription, serverPrivate *ecdh.PrivateKey, salt []byte) ([]byte, []byte, error) {
	if len(payload) == 0 || len(payload) > 2048 || len(subscription.P256DH) != 65 || subscription.P256DH[0] != 4 || len(subscription.Auth) != 16 || serverPrivate == nil || len(salt) != 16 {
		return nil, nil, errors.New("web push subscription keys are invalid")
	}
	clientPublic, err := ecdh.P256().NewPublicKey(subscription.P256DH)
	if err != nil {
		return nil, nil, errors.New("web push subscription public key is invalid")
	}
	shared, err := serverPrivate.ECDH(clientPublic)
	if err != nil {
		return nil, nil, errors.New("derive web push content key")
	}
	serverPublic := serverPrivate.PublicKey().Bytes()
	keyInfo := append([]byte("WebPush: info\x00"), subscription.P256DH...)
	keyInfo = append(keyInfo, serverPublic...)
	prkKey := hkdfExtract(subscription.Auth, shared)
	ikm := hkdfExpand(prkKey, keyInfo, 32)
	prk := hkdfExtract(salt, ikm)
	contentKey := hkdfExpand(prk, []byte("Content-Encoding: aes128gcm\x00"), 16)
	nonce := hkdfExpand(prk, []byte("Content-Encoding: nonce\x00"), 12)
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, nil, errors.New("create web push cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, errors.New("create web push authenticated cipher")
	}
	plaintext := append(append([]byte(nil), payload...), 2)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	recordSize := uint32(4096)
	body := make([]byte, 0, 16+4+1+len(serverPublic)+len(ciphertext))
	body = append(body, salt...)
	record := make([]byte, 4)
	binary.BigEndian.PutUint32(record, recordSize)
	body = append(body, record...)
	body = append(body, byte(len(serverPublic)))
	body = append(body, serverPublic...)
	body = append(body, ciphertext...)
	return body, serverPublic, nil
}

func (s *Sender) vapid(endpoint *url.URL, now time.Time, random io.Reader) (string, error) {
	header, _ := json.Marshal(struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
	}{"JWT", "ES256"})
	audience := endpoint.Scheme + "://" + strings.ToLower(endpoint.Hostname())
	payload, _ := json.Marshal(struct {
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		Subject  string `json:"sub"`
	}{audience, now.UTC().Add(12 * time.Hour).Unix(), s.subject})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	d := new(big.Int).SetBytes(s.private.Bytes())
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(s.private.Bytes())
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	r, signatureS, err := ecdsa.Sign(random, private, digest[:])
	if err != nil {
		return "", errors.New("sign VAPID token")
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func hkdfExtract(salt, input []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(input)
	return mac.Sum(nil)
}

func hkdfExpand(key, info []byte, length int) []byte {
	var output, previous []byte
	for counter := byte(1); len(output) < length; counter++ {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		output = append(output, previous...)
	}
	return output[:length]
}
