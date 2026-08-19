// SPDX-License-Identifier: AGPL-3.0-only

package webpush

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"gamertan.com/observatory/internal/identity"
	"gamertan.com/observatory/internal/storage"
	"gamertan.com/web/access"
)

type subscriptionStore interface {
	PushSubscriptions(context.Context, string) ([]storage.PushSubscription, error)
	RecordPushResult(context.Context, string, string, string, time.Time) error
	DeletePushSubscription(context.Context, string, string, string) (bool, error)
}

type authorizer interface {
	Authorize(context.Context, string, access.Scope, string) (access.Decision, error)
}

type notificationSender interface {
	Send(context.Context, Subscription) error
}

type Notifier struct {
	store      subscriptionStore
	authorizer authorizer
	sender     notificationSender
	queue      chan string
	now        func() time.Time
	pendingMu  sync.Mutex
	pending    map[string]struct{}
	enqueued   atomic.Uint64
	delivered  atomic.Uint64
	failed     atomic.Uint64
	dropped    atomic.Uint64
}

type NotifierStats struct {
	Enqueued  uint64
	Delivered uint64
	Failed    uint64
	Dropped   uint64
}

func NewNotifier(store subscriptionStore, authorizer authorizer, sender notificationSender, capacity int) (*Notifier, error) {
	if store == nil || authorizer == nil || sender == nil || capacity < 1 || capacity > 1024 {
		return nil, errors.New("web push notifier options are invalid")
	}
	return &Notifier{store: store, authorizer: authorizer, sender: sender, queue: make(chan string, capacity), now: func() time.Time { return time.Now().UTC() }, pending: map[string]struct{}{}}, nil
}

// Enqueue records only an opaque organization identity in a bounded in-memory
// queue. A full queue or duplicate pending organization is deliberately
// nonblocking: alert evaluation and incident persistence remain authoritative.
func (n *Notifier) Enqueue(organizationID string) bool {
	n.pendingMu.Lock()
	if _, exists := n.pending[organizationID]; exists {
		n.pendingMu.Unlock()
		return true
	}
	n.pending[organizationID] = struct{}{}
	n.pendingMu.Unlock()
	select {
	case n.queue <- organizationID:
		n.enqueued.Add(1)
		return true
	default:
		n.pendingMu.Lock()
		delete(n.pending, organizationID)
		n.pendingMu.Unlock()
		n.dropped.Add(1)
		return false
	}
}

func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case organizationID := <-n.queue:
			n.deliver(ctx, organizationID)
			n.pendingMu.Lock()
			delete(n.pending, organizationID)
			n.pendingMu.Unlock()
		}
	}
}

func (n *Notifier) Stats() NotifierStats {
	return NotifierStats{Enqueued: n.enqueued.Load(), Delivered: n.delivered.Load(), Failed: n.failed.Load(), Dropped: n.dropped.Load()}
}

func (n *Notifier) deliver(ctx context.Context, organizationID string) {
	subscriptions, err := n.store.PushSubscriptions(ctx, organizationID)
	if err != nil {
		n.failed.Add(1)
		return
	}
	for _, subscription := range subscriptions {
		decision, authErr := n.authorizer.Authorize(ctx, subscription.UserID, access.Scope{OrganizationID: organizationID}, identity.PermissionIncidentsRead)
		if authErr != nil {
			n.failed.Add(1)
			continue
		}
		if !decision.Allowed {
			_, _ = n.store.DeletePushSubscription(ctx, organizationID, subscription.UserID, subscription.Endpoint)
			continue
		}
		deliveryErr := n.sender.Send(ctx, Subscription{Endpoint: subscription.Endpoint, P256DH: subscription.P256DH, Auth: subscription.Auth})
		outcome := "sent"
		if errors.Is(deliveryErr, ErrSubscriptionGone) {
			outcome = "gone"
		} else if deliveryErr != nil {
			outcome = "failed"
		}
		if recordErr := n.store.RecordPushResult(ctx, organizationID, subscription.ID, outcome, n.now()); recordErr != nil || deliveryErr != nil {
			n.failed.Add(1)
			continue
		}
		n.delivered.Add(1)
	}
}
