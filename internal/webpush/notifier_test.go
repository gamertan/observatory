// SPDX-License-Identifier: AGPL-3.0-only

package webpush

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/access"
)

type fakePushStore struct {
	subscriptions []storage.PushSubscription
	mu            sync.Mutex
	results       []string
	deleted       []string
}

func (store *fakePushStore) DeletePushSubscription(_ context.Context, organizationID, userID, endpoint string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.deleted = append(store.deleted, organizationID+"/"+userID+"/"+endpoint)
	return false, nil
}

func (store *fakePushStore) PushSubscriptions(context.Context, string) ([]storage.PushSubscription, error) {
	return append([]storage.PushSubscription(nil), store.subscriptions...), nil
}

func (store *fakePushStore) RecordPushResult(_ context.Context, _, _ string, result string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.results = append(store.results, result)
	return nil
}

type fakeAuthorizer struct{ allowed map[string]bool }

func (authorizer fakeAuthorizer) Authorize(_ context.Context, userID string, _ access.Scope, permission string) (access.Decision, error) {
	if permission != "incidents.read" {
		return access.Decision{}, errors.New("unexpected permission")
	}
	return access.Decision{Allowed: authorizer.allowed[userID]}, nil
}

type fakeNotificationSender struct {
	mu       sync.Mutex
	requests []Subscription
	err      error
}

func (sender *fakeNotificationSender) Send(_ context.Context, subscription Subscription) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.requests = append(sender.requests, subscription)
	return sender.err
}

func TestNotifierIsBoundedDeduplicatedAndAuthorizationAware(t *testing.T) {
	store := &fakePushStore{subscriptions: []storage.PushSubscription{
		{OrganizationID: "organization-a", ID: "push-a", UserID: "user-a", Endpoint: "https://push.example.test/a", P256DH: make([]byte, 65), Auth: make([]byte, 16)},
		{OrganizationID: "organization-a", ID: "push-b", UserID: "user-b", Endpoint: "https://push.example.test/b", P256DH: make([]byte, 65), Auth: make([]byte, 16)},
	}}
	sender := &fakeNotificationSender{}
	notifier, err := NewNotifier(store, fakeAuthorizer{allowed: map[string]bool{"user-a": true}}, sender, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !notifier.Enqueue("organization-a") || !notifier.Enqueue("organization-a") {
		t.Fatal("duplicate pending organization was not accepted as already queued")
	}
	if notifier.Enqueue("organization-b") {
		t.Fatal("full queue accepted a second organization")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { notifier.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for notifier.Stats().Delivered != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if len(sender.requests) != 1 || sender.requests[0].Endpoint != "https://push.example.test/a" {
		t.Fatalf("requests=%+v", sender.requests)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.results) != 1 || store.results[0] != "sent" || len(store.deleted) != 1 || !strings.Contains(store.deleted[0], "/user-b/") {
		t.Fatalf("results=%v deleted=%v", store.results, store.deleted)
	}
	stats := notifier.Stats()
	if stats.Enqueued != 1 || stats.Delivered != 1 || stats.Dropped != 1 || stats.Failed != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestNotifierDeliveryFailureNeverBlocksEnqueue(t *testing.T) {
	store := &fakePushStore{subscriptions: []storage.PushSubscription{{OrganizationID: "organization-a", ID: "push-a", UserID: "user-a", Endpoint: "https://push.example.test/a", P256DH: make([]byte, 65), Auth: make([]byte, 16)}}}
	notifier, err := NewNotifier(store, fakeAuthorizer{allowed: map[string]bool{"user-a": true}}, &fakeNotificationSender{err: errors.New("offline")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !notifier.Enqueue("organization-a") {
		t.Fatal("enqueue failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { notifier.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for notifier.Stats().Failed == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if notifier.Stats().Failed != 1 || len(store.results) != 1 || store.results[0] != "failed" {
		t.Fatalf("stats=%+v results=%v", notifier.Stats(), store.results)
	}
}
