// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
	"unicode/utf8"

	"gamertan.com/observatory/internal/model"
)

const (
	MaxPushSubscriptionsPerUser = 8
	MaxPushSubscriptionsPerPass = 256
)

type PushSubscription struct {
	OrganizationID string
	ID             string
	UserID         string
	Endpoint       string
	P256DH         []byte
	Auth           []byte
	FailureCount   int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastSentAt     *time.Time
}

type PushSubscriptionInput struct {
	OrganizationID string
	UserID         string
	Endpoint       string
	P256DH         []byte
	Auth           []byte
}

func (s *Store) SavePushSubscription(ctx context.Context, input PushSubscriptionInput, now time.Time) (PushSubscription, error) {
	if err := validatePushSubscription(input); err != nil {
		return PushSubscription{}, err
	}
	digest := sha256.Sum256([]byte(input.Endpoint))
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return PushSubscription{}, errors.New("save push subscription")
	}
	defer tx.Rollback()
	var endpointID, endpointUser string
	err = tx.QueryRowContext(ctx, `SELECT id,user_id FROM push_endpoints WHERE endpoint_digest=?`, digest[:]).Scan(&endpointID, &endpointUser)
	switch {
	case err == nil:
		if endpointUser != input.UserID {
			return PushSubscription{}, errors.New("push subscription is already registered")
		}
		_, err = tx.ExecContext(ctx, `UPDATE push_endpoints SET endpoint=?,p256dh=?,auth_secret=?,active=1,failure_count=0,updated_at=? WHERE id=?`, input.Endpoint, input.P256DH, input.Auth, now.UTC().Format(time.RFC3339Nano), endpointID)
	case errors.Is(err, sql.ErrNoRows):
		endpointID, err = storageID("endpoint")
		if err == nil {
			stamp := now.UTC().Format(time.RFC3339Nano)
			_, err = tx.ExecContext(ctx, `INSERT INTO push_endpoints(id,user_id,endpoint,endpoint_digest,p256dh,auth_secret,active,failure_count,created_at,updated_at) VALUES(?,?,?,?,?,?,1,0,?,?)`, endpointID, input.UserID, input.Endpoint, digest[:], input.P256DH, input.Auth, stamp, stamp)
		}
	default:
		return PushSubscription{}, errors.New("save push subscription")
	}
	if err != nil {
		return PushSubscription{}, errors.New("save push subscription")
	}
	var subscriptionID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM push_subscriptions WHERE organization_id=? AND user_id=? AND endpoint_id=?`, input.OrganizationID, input.UserID, endpointID).Scan(&subscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_subscriptions WHERE organization_id=? AND user_id=?`, input.OrganizationID, input.UserID).Scan(&count); err != nil {
			return PushSubscription{}, errors.New("save push subscription")
		}
		if count >= MaxPushSubscriptionsPerUser {
			return PushSubscription{}, errors.New("push subscription limit reached")
		}
		subscriptionID, err = storageID("push")
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO push_subscriptions(organization_id,id,user_id,endpoint_id,created_at) VALUES(?,?,?,?,?)`, input.OrganizationID, subscriptionID, input.UserID, endpointID, now.UTC().Format(time.RFC3339Nano))
		}
	}
	if err != nil {
		return PushSubscription{}, errors.New("save push subscription")
	}
	if err = tx.Commit(); err != nil {
		return PushSubscription{}, errors.New("save push subscription")
	}
	return s.PushSubscription(ctx, input.OrganizationID, subscriptionID)
}

func (s *Store) HasPushSubscription(ctx context.Context, organizationID, userID, endpoint string) (bool, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(userID) != nil || !utf8.ValidString(endpoint) || len(endpoint) < 1 || len(endpoint) > 2048 {
		return false, errors.New("push subscription lookup is invalid")
	}
	digest := sha256.Sum256([]byte(endpoint))
	var count int
	err := s.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_subscriptions s JOIN push_endpoints e ON e.id=s.endpoint_id WHERE s.organization_id=? AND s.user_id=? AND e.endpoint_digest=? AND e.active=1`, organizationID, userID, digest[:]).Scan(&count)
	if err != nil {
		return false, errors.New("lookup push subscription")
	}
	return count == 1, nil
}

// DeletePushSubscription removes one organization mapping. The returned
// value reports whether the browser endpoint remains mapped elsewhere for
// the same user and therefore must remain subscribed in the user agent.
func (s *Store) DeletePushSubscription(ctx context.Context, organizationID, userID, endpoint string) (bool, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(userID) != nil || !utf8.ValidString(endpoint) || len(endpoint) < 1 || len(endpoint) > 2048 {
		return false, errors.New("push subscription deletion is invalid")
	}
	digest := sha256.Sum256([]byte(endpoint))
	tx, err := s.control.BeginTx(ctx, nil)
	if err != nil {
		return false, errors.New("delete push subscription")
	}
	defer tx.Rollback()
	var endpointID string
	err = tx.QueryRowContext(ctx, `SELECT e.id FROM push_subscriptions s JOIN push_endpoints e ON e.id=s.endpoint_id WHERE s.organization_id=? AND s.user_id=? AND e.endpoint_digest=?`, organizationID, userID, digest[:]).Scan(&endpointID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errors.New("push subscription not found")
	}
	if err != nil {
		return false, errors.New("delete push subscription")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE organization_id=? AND user_id=? AND endpoint_id=?`, organizationID, userID, endpointID); err != nil {
		return false, errors.New("delete push subscription")
	}
	var remaining int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_subscriptions WHERE endpoint_id=?`, endpointID).Scan(&remaining); err != nil {
		return false, errors.New("delete push subscription")
	}
	if remaining == 0 {
		if _, err = tx.ExecContext(ctx, `DELETE FROM push_endpoints WHERE id=?`, endpointID); err != nil {
			return false, errors.New("delete push subscription")
		}
	}
	if err = tx.Commit(); err != nil {
		return false, errors.New("delete push subscription")
	}
	return remaining > 0, nil
}

func (s *Store) PushSubscription(ctx context.Context, organizationID, id string) (PushSubscription, error) {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(id) != nil {
		return PushSubscription{}, errors.New("push subscription identity is invalid")
	}
	return scanPushSubscription(s.control.QueryRowContext(ctx, `SELECT s.organization_id,s.id,s.user_id,e.endpoint,e.p256dh,e.auth_secret,e.failure_count,s.created_at,e.updated_at,e.last_sent_at FROM push_subscriptions s JOIN push_endpoints e ON e.id=s.endpoint_id WHERE s.organization_id=? AND s.id=? AND e.active=1`, organizationID, id))
}

func (s *Store) PushSubscriptions(ctx context.Context, organizationID string) ([]PushSubscription, error) {
	if model.ValidateSourceID(organizationID) != nil {
		return nil, errors.New("organization identity is invalid")
	}
	rows, err := s.control.QueryContext(ctx, `SELECT s.organization_id,s.id,s.user_id,e.endpoint,e.p256dh,e.auth_secret,e.failure_count,s.created_at,e.updated_at,e.last_sent_at FROM push_subscriptions s JOIN push_endpoints e ON e.id=s.endpoint_id WHERE s.organization_id=? AND e.active=1 ORDER BY s.id LIMIT ?`, organizationID, MaxPushSubscriptionsPerPass)
	if err != nil {
		return nil, errors.New("list push subscriptions")
	}
	defer rows.Close()
	var subscriptions []PushSubscription
	for rows.Next() {
		subscription, scanErr := scanPushSubscription(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		subscriptions = append(subscriptions, subscription)
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("list push subscriptions")
	}
	return subscriptions, nil
}

func (s *Store) RecordPushResult(ctx context.Context, organizationID, id string, outcome string, now time.Time) error {
	if model.ValidateSourceID(organizationID) != nil || model.ValidateSourceID(id) != nil {
		return errors.New("push subscription identity is invalid")
	}
	var result sql.Result
	var err error
	switch outcome {
	case "sent":
		result, err = s.control.ExecContext(ctx, `UPDATE push_endpoints SET failure_count=0,last_sent_at=?,updated_at=? WHERE id=(SELECT endpoint_id FROM push_subscriptions WHERE organization_id=? AND id=?) AND active=1`, now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano), organizationID, id)
	case "gone":
		result, err = s.control.ExecContext(ctx, `UPDATE push_endpoints SET active=0,updated_at=? WHERE id=(SELECT endpoint_id FROM push_subscriptions WHERE organization_id=? AND id=?) AND active=1`, now.UTC().Format(time.RFC3339Nano), organizationID, id)
	case "failed":
		result, err = s.control.ExecContext(ctx, `UPDATE push_endpoints SET failure_count=failure_count+1,active=CASE WHEN failure_count+1>=5 THEN 0 ELSE 1 END,updated_at=? WHERE id=(SELECT endpoint_id FROM push_subscriptions WHERE organization_id=? AND id=?) AND active=1`, now.UTC().Format(time.RFC3339Nano), organizationID, id)
	default:
		return errors.New("push delivery outcome is invalid")
	}
	if err != nil {
		return errors.New("record push delivery result")
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("push subscription not found")
	}
	return nil
}

func scanPushSubscription(row rowScanner) (PushSubscription, error) {
	var subscription PushSubscription
	var createdAt, updatedAt string
	var lastSent sql.NullString
	if err := row.Scan(&subscription.OrganizationID, &subscription.ID, &subscription.UserID, &subscription.Endpoint, &subscription.P256DH, &subscription.Auth, &subscription.FailureCount, &createdAt, &updatedAt, &lastSent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PushSubscription{}, errors.New("push subscription not found")
		}
		return PushSubscription{}, errors.New("read push subscription")
	}
	var err error
	if subscription.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return PushSubscription{}, errors.New("read push subscription")
	}
	if subscription.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
		return PushSubscription{}, errors.New("read push subscription")
	}
	if lastSent.Valid {
		parsed, parseErr := time.Parse(time.RFC3339Nano, lastSent.String)
		if parseErr != nil {
			return PushSubscription{}, errors.New("read push subscription")
		}
		subscription.LastSentAt = &parsed
	}
	return subscription, nil
}

func validatePushSubscription(input PushSubscriptionInput) error {
	if model.ValidateSourceID(input.OrganizationID) != nil || model.ValidateSourceID(input.UserID) != nil {
		return errors.New("push subscription scope is invalid")
	}
	if !utf8.ValidString(input.Endpoint) || len(input.Endpoint) < 1 || len(input.Endpoint) > 2048 || len(input.P256DH) != 65 || len(input.Auth) != 16 {
		return errors.New("push subscription material is invalid")
	}
	return nil
}
