// SPDX-License-Identifier: AGPL-3.0-only

package webpush

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestSenderUsesEncryptedGenericPayloadAndValidVAPID(t *testing.T) {
	serverKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err = rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	var captured *http.Request
	var encrypted []byte
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(context.Background())
		encrypted, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("accepted")), Header: make(http.Header)}, nil
	})}
	fixed := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	sender, err := New(Options{PrivateKey: serverKey.Bytes(), Subject: "mailto:security@sandwichhime.com", Timeout: 5 * time.Second, Client: client, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	subscription := Subscription{Endpoint: "https://push.example.test/send/opaque-token", P256DH: clientKey.PublicKey().Bytes(), Auth: auth}
	if err = sender.Send(context.Background(), subscription); err != nil {
		t.Fatal(err)
	}
	if captured == nil || captured.Method != http.MethodPost || captured.URL.String() != subscription.Endpoint {
		t.Fatalf("request=%v", captured)
	}
	if captured.Header.Get("Content-Encoding") != "aes128gcm" || captured.Header.Get("TTL") != "300" || captured.Header.Get("Urgency") != "high" {
		t.Fatalf("headers=%v", captured.Header)
	}
	if len(encrypted) < 100 || strings.Contains(string(encrypted), GenericMessage) {
		t.Fatalf("payload length=%d plaintext=%t", len(encrypted), strings.Contains(string(encrypted), GenericMessage))
	}
	if decrypted := decryptTestPayload(t, encrypted, clientKey, auth); string(decrypted) != GenericMessage {
		t.Fatalf("decrypted=%q", decrypted)
	}
	authorization := captured.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "vapid t=") || !strings.Contains(authorization, ", k="+sender.PublicKey()) {
		t.Fatalf("authorization=%q", authorization)
	}
	token := strings.TrimPrefix(strings.Split(authorization, ", k=")[0], "vapid t=")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts=%d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		Subject  string `json:"sub"`
	}
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Audience != "https://push.example.test" || payload.Subject != "mailto:security@sandwichhime.com" || payload.Expiry != fixed.Add(12*time.Hour).Unix() {
		t.Fatalf("payload=%+v", payload)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature length=%d err=%v", len(signature), err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(sender.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("VAPID signature did not verify")
	}
}

func TestEncryptionMatchesRFC8291SectionFiveVector(t *testing.T) {
	decode := func(value string) []byte {
		t.Helper()
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	serverPrivate, err := ecdh.P256().NewPrivateKey(decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	subscription := Subscription{
		P256DH: decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
		Auth:   decode("BTBZMqHH6r4Tts7J_aSIgg"),
	}
	payload := decode("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24")
	body, _, err := encryptWithMaterial(payload, subscription, serverPrivate, decode("DGv6ra1nlYgDCS1FRnbzlw"))
	if err != nil {
		t.Fatal(err)
	}
	expected := decode("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
	if string(body) != string(expected) {
		t.Fatalf("RFC 8291 vector mismatch\n got: %s\nwant: %s", base64.RawURLEncoding.EncodeToString(body), base64.RawURLEncoding.EncodeToString(expected))
	}
}

func TestSenderClassifiesGoneSubscription(t *testing.T) {
	serverKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	clientKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	sender, err := New(Options{PrivateKey: serverKey.Bytes(), Subject: "https://observatory.example/security", Timeout: time.Second, Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusGone, Body: io.NopCloser(strings.NewReader("expired")), Header: make(http.Header)}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(context.Background(), Subscription{Endpoint: "https://push.example.test/s/expired", P256DH: clientKey.PublicKey().Bytes(), Auth: auth})
	if !errors.Is(err, ErrSubscriptionGone) {
		t.Fatalf("err=%v", err)
	}
}

func TestEndpointAndAddressValidation(t *testing.T) {
	valid := []string{"https://push.example.test/send/token", "https://push.example.test:443/send/token", "https://push.example.test/send/token?opaque=one"}
	for _, candidate := range valid {
		if _, err := ValidateEndpoint(candidate); err != nil {
			t.Errorf("valid endpoint %q: %v", candidate, err)
		}
	}
	invalid := []string{
		"http://push.example.test/send/token", "https://localhost/send/token", "https://127.0.0.1/send/token",
		"https://push.example.test:8443/send/token", "https://user@push.example.test/send/token", "https://push.example.test",
		"https://push.example.test/send/token#secret",
	}
	for _, candidate := range invalid {
		if _, err := ValidateEndpoint(candidate); err == nil {
			t.Errorf("invalid endpoint accepted: %q", candidate)
		}
	}
	for _, candidate := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "::1", "fc00::1", "fe80::1"} {
		if publicIP(net.ParseIP(candidate)) {
			t.Errorf("non-public address accepted: %s", candidate)
		}
	}
	for _, candidate := range []string{"100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "2001:db8::1"} {
		if publicIP(net.ParseIP(candidate)) {
			t.Errorf("special-use address accepted: %s", candidate)
		}
	}
	for _, candidate := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(candidate)) {
			t.Errorf("public address rejected: %s", candidate)
		}
	}
}

func TestSenderRejectsInvalidInputs(t *testing.T) {
	private, _ := ecdh.P256().GenerateKey(rand.Reader)
	for _, test := range []Options{
		{PrivateKey: []byte("short"), Subject: "mailto:security@example.test", Timeout: time.Second},
		{PrivateKey: private.Bytes(), Subject: "javascript:alert(1)", Timeout: time.Second},
		{PrivateKey: private.Bytes(), Subject: "mailto:security@example.test", Timeout: time.Millisecond},
	} {
		if _, err := New(test); err == nil {
			t.Fatalf("invalid options accepted: %+v", test)
		}
	}
}

func decryptTestPayload(t *testing.T, body []byte, clientPrivate *ecdh.PrivateKey, auth []byte) []byte {
	t.Helper()
	if len(body) < 16+4+1+65+16 || binary.BigEndian.Uint32(body[16:20]) != 4096 || body[20] != 65 {
		t.Fatalf("invalid aes128gcm record length=%d", len(body))
	}
	return decryptWithAuth(t, body, clientPrivate, auth)
}

func decryptWithAuth(t *testing.T, body []byte, clientPrivate *ecdh.PrivateKey, auth []byte) []byte {
	t.Helper()
	salt := body[:16]
	serverPublicBytes := body[21:86]
	serverPublic, err := ecdh.P256().NewPublicKey(serverPublicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := clientPrivate.ECDH(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo := append([]byte("WebPush: info\x00"), clientPrivate.PublicKey().Bytes()...)
	keyInfo = append(keyInfo, serverPublicBytes...)
	ikm := hkdfExpand(hkdfExtract(auth, shared), keyInfo, 32)
	prk := hkdfExtract(salt, ikm)
	block, err := aes.NewCipher(hkdfExpand(prk, []byte("Content-Encoding: aes128gcm\x00"), 16))
	if err != nil {
		t.Fatal(err)
	}
	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, hkdfExpand(prk, []byte("Content-Encoding: nonce\x00"), 12), body[86:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plaintext) < 1 || plaintext[len(plaintext)-1] != 2 {
		t.Fatalf("invalid record delimiter: %x", plaintext)
	}
	return plaintext[:len(plaintext)-1]
}
