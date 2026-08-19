// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

func TestPushSubscriptionLifecycleAndOwnership(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	input := pushInput("organization-a", "user-a", "https://push.example.test/send/one")
	created, err := store.SavePushSubscription(context.Background(), input, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.OrganizationID != input.OrganizationID || created.UserID != input.UserID || created.Endpoint != input.Endpoint || created.FailureCount != 0 {
		t.Fatalf("created=%+v", created)
	}
	input.P256DH[10] ^= 0xff
	updated, err := store.SavePushSubscription(context.Background(), input, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.P256DH[10] != input.P256DH[10] {
		t.Fatalf("updated=%+v", updated)
	}
	claimed := input
	claimed.UserID = "user-b"
	if _, err = store.SavePushSubscription(context.Background(), claimed, now); err == nil {
		t.Fatal("another user claimed an existing endpoint")
	}
	if _, err = store.DeletePushSubscription(context.Background(), input.OrganizationID, "user-b", input.Endpoint); err == nil {
		t.Fatal("another user deleted an existing endpoint")
	}
	otherOrganization := input
	otherOrganization.OrganizationID = "organization-b"
	other, err := store.SavePushSubscription(context.Background(), otherOrganization, now.Add(2*time.Minute))
	if err != nil || other.ID == created.ID {
		t.Fatalf("other organization=%+v err=%v", other, err)
	}
	for _, organizationID := range []string{input.OrganizationID, otherOrganization.OrganizationID} {
		if subscribed, statusErr := store.HasPushSubscription(context.Background(), organizationID, input.UserID, input.Endpoint); statusErr != nil || !subscribed {
			t.Fatalf("organization=%s subscribed=%t err=%v", organizationID, subscribed, statusErr)
		}
	}
	remaining, err := store.DeletePushSubscription(context.Background(), input.OrganizationID, input.UserID, input.Endpoint)
	if err != nil || !remaining {
		t.Fatal(err)
	}
	if subscriptions, listErr := store.PushSubscriptions(context.Background(), input.OrganizationID); listErr != nil || len(subscriptions) != 0 {
		t.Fatalf("subscriptions=%+v err=%v", subscriptions, listErr)
	}
	remaining, err = store.DeletePushSubscription(context.Background(), otherOrganization.OrganizationID, input.UserID, input.Endpoint)
	if err != nil || remaining {
		t.Fatalf("remaining=%t err=%v", remaining, err)
	}
}

func TestPushDeliveryResultsAreBounded(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	created, err := store.SavePushSubscription(context.Background(), pushInput("organization-a", "user-a", "https://push.example.test/send/result"), now)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 4; attempt++ {
		if err = store.RecordPushResult(context.Background(), created.OrganizationID, created.ID, "failed", now.Add(time.Duration(attempt)*time.Minute)); err != nil {
			t.Fatal(err)
		}
		current, currentErr := store.PushSubscription(context.Background(), created.OrganizationID, created.ID)
		if currentErr != nil || current.FailureCount != attempt {
			t.Fatalf("attempt=%d current=%+v err=%v", attempt, current, currentErr)
		}
	}
	if err = store.RecordPushResult(context.Background(), created.OrganizationID, created.ID, "sent", now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	current, err := store.PushSubscription(context.Background(), created.OrganizationID, created.ID)
	if err != nil || current.FailureCount != 0 || current.LastSentAt == nil {
		t.Fatalf("sent current=%+v err=%v", current, err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if err = store.RecordPushResult(context.Background(), created.OrganizationID, created.ID, "failed", now.Add(time.Duration(6+attempt)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = store.PushSubscription(context.Background(), created.OrganizationID, created.ID); err == nil {
		t.Fatal("five delivery failures did not disable the subscription")
	}
	if subscriptions, listErr := store.PushSubscriptions(context.Background(), created.OrganizationID); listErr != nil || len(subscriptions) != 0 {
		t.Fatalf("subscriptions=%+v err=%v", subscriptions, listErr)
	}
}

func TestPushSubscriptionLimit(t *testing.T) {
	store := testStore(t)
	defer store.Close()
	var err error
	for index := 0; index < MaxPushSubscriptionsPerUser; index++ {
		input := pushInput("organization-a", "user-a", "https://push.example.test/send/limit"+string(rune('a'+index)))
		if _, err = store.SavePushSubscription(context.Background(), input, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = store.SavePushSubscription(context.Background(), pushInput("organization-a", "user-a", "https://push.example.test/send/overflow"), time.Now()); err == nil {
		t.Fatal("subscription limit was not enforced")
	}
}

func TestControlSchemaFiveMigratesToPushSchema(t *testing.T) {
	database := openSchemaDatabase(t, 5)
	defer database.Close()
	if err := migrateControl(database); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := database.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil || version != controlSchema {
		t.Fatalf("version=%d err=%v", version, err)
	}
	for _, name := range []string{"push_endpoints", "push_subscriptions"} {
		var table int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&table); err != nil || table != 1 {
			t.Fatalf("table=%s count=%d err=%v", name, table, err)
		}
	}
}

func pushInput(organizationID, userID, endpoint string) PushSubscriptionInput {
	key := make([]byte, 65)
	auth := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(auth)
	key[0] = 4
	return PushSubscriptionInput{OrganizationID: organizationID, UserID: userID, Endpoint: endpoint, P256DH: key, Auth: auth}
}
