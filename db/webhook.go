// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"time"
)

type WebhookSub struct {
	ID      int       `json:"id"`
	URL     string    `json:"url"`
	Events  string    `json:"events"`
	Enabled bool      `json:"enabled"`
	Created time.Time `json:"created"`
}

func CreateWebhookSub(d *DB, url, events string) (*WebhookSub, error) {
	if events == "" {
		events = "issue,revoke,expiry"
	}
	id, err := d.InsertReturning(`INSERT INTO webhook_subscriptions (url, events) VALUES (?, ?)`, url, events)
	if err != nil {
		return nil, fmt.Errorf("create webhook sub: %w", err)
	}
	return GetWebhookSub(d, int(id))
}

func ListWebhookSubs(d *DB) ([]WebhookSub, error) {
	rows, err := d.Query(`SELECT id, url, events, enabled, created FROM webhook_subscriptions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list webhook subs: %w", err)
	}
	defer rows.Close()
	var subs []WebhookSub
	for rows.Next() {
		var s WebhookSub
		var createdStr string
		if err := rows.Scan(&s.ID, &s.URL, &s.Events, &s.Enabled, &createdStr); err != nil {
			return nil, fmt.Errorf("scan webhook sub: %w", err)
		}
		s.Created, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		subs = append(subs, s)
	}
	return subs, rows.Err()
}

func GetWebhookSub(d *DB, id int) (*WebhookSub, error) {
	var s WebhookSub
	var createdStr string
	err := d.QueryRow(`SELECT id, url, events, enabled, created FROM webhook_subscriptions WHERE id = ?`, id).
		Scan(&s.ID, &s.URL, &s.Events, &s.Enabled, &createdStr)
	if err != nil {
		return nil, fmt.Errorf("get webhook sub %d: %w", id, err)
	}
	s.Created, _ = time.Parse("2006-01-02 15:04:05", createdStr)
	return &s, nil
}

func DeleteWebhookSub(d *DB, id int) error {
	res, err := d.Exec(`DELETE FROM webhook_subscriptions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete webhook sub %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("webhook sub %d not found", id)
	}
	return nil
}
