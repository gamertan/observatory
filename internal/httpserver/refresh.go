// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"errors"
	"sync"
)

var errRefreshCapacity = errors.New("live refresh capacity reached")

// refreshHub carries only a coalescible invalidation signal. It never carries
// telemetry, resource names, incident details, or credentials.
type refreshHub struct {
	mu                 sync.Mutex
	next               uint64
	total              int
	maxTotal           int
	maxPerOrganization int
	subscribers        map[string]map[uint64]chan struct{}
}

func newRefreshHub(maxTotal, maxPerOrganization int) *refreshHub {
	return &refreshHub{maxTotal: maxTotal, maxPerOrganization: maxPerOrganization, subscribers: make(map[string]map[uint64]chan struct{})}
}

func (hub *refreshHub) subscribe(organizationID string) (<-chan struct{}, func(), error) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	group := hub.subscribers[organizationID]
	if hub.total >= hub.maxTotal || len(group) >= hub.maxPerOrganization {
		return nil, nil, errRefreshCapacity
	}
	if group == nil {
		group = make(map[uint64]chan struct{})
		hub.subscribers[organizationID] = group
	}
	hub.next++
	id := hub.next
	updates := make(chan struct{}, 1)
	group[id] = updates
	hub.total++
	var once sync.Once
	remove := func() {
		once.Do(func() {
			hub.mu.Lock()
			defer hub.mu.Unlock()
			if current := hub.subscribers[organizationID]; current != nil {
				if _, exists := current[id]; exists {
					delete(current, id)
					hub.total--
				}
				if len(current) == 0 {
					delete(hub.subscribers, organizationID)
				}
			}
		})
	}
	return updates, remove, nil
}

func (hub *refreshHub) publish(organizationID string) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for _, updates := range hub.subscribers[organizationID] {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}
