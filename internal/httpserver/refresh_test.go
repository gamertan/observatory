// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"errors"
	"testing"
)

func TestRefreshHubIsBoundedCoalescedAndOrganizationScoped(t *testing.T) {
	hub := newRefreshHub(2, 1)
	first, removeFirst, err := hub.subscribe("organization-a")
	if err != nil {
		t.Fatal(err)
	}
	defer removeFirst()
	if _, _, err = hub.subscribe("organization-a"); !errors.Is(err, errRefreshCapacity) {
		t.Fatalf("same-organization capacity err=%v", err)
	}
	second, removeSecond, err := hub.subscribe("organization-b")
	if err != nil {
		t.Fatal(err)
	}
	defer removeSecond()
	if _, _, err = hub.subscribe("organization-c"); !errors.Is(err, errRefreshCapacity) {
		t.Fatalf("total capacity err=%v", err)
	}

	hub.publish("organization-a")
	hub.publish("organization-a")
	select {
	case <-first:
	default:
		t.Fatal("organization A did not receive refresh")
	}
	select {
	case <-first:
		t.Fatal("duplicate refresh was not coalesced")
	default:
	}
	select {
	case <-second:
		t.Fatal("organization B received organization A refresh")
	default:
	}

	removeFirst()
	if _, removeReplacement, err := hub.subscribe("organization-a"); err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	} else {
		removeReplacement()
	}
}
