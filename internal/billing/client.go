// Package billing connects relay to billing-service in realtime.
//
// Relay enforces tiers locally (cached, fail-open) and reports metered usage
// upstream. Env:
//
//	BILLING_URL      e.g. http://billing:8080 (empty = billing disabled)
//	BILLING_API_KEY  Bearer key for billing-service /v1
//	BILLING_ORG_ID   org uuid for usage reports + entitlement lookups
//
// Cadence: FetchTier caches for 5 minutes; ReportUsage is called by the
// forwarder every 60s with an idempotency key of org:events:YYYYMMDDHHMM so
// replays dedupe server-side. A billing outage never blocks ingest — the last
// known tier stays active and usage is retried on the next tick.
package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config for the live billing link.
type Config struct {
	URL    string
	APIKey string
	OrgID  string
	Client *http.Client
}

// ConfigFromEnv loads the link. Enabled() == false means run standalone.
func ConfigFromEnv() Config {
	return Config{
		URL:    strings.TrimRight(strings.TrimSpace(os.Getenv("BILLING_URL")), "/"),
		APIKey: strings.TrimSpace(os.Getenv("BILLING_API_KEY")),
		OrgID:  strings.TrimSpace(os.Getenv("BILLING_ORG_ID")),
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether live calls should be attempted.
func (c Config) Enabled() bool { return c.URL != "" && c.APIKey != "" && c.OrgID != "" }

// Tier is the cached entitlement snapshot relay enforces.
type Tier struct {
	Plan            string `json:"tier"`
	MaxDevices      int64  `json:"max_devices"`
	MaxEventsPerDay int64  `json:"max_events_per_day"`
	FetchedAt       time.Time
}

// Cache holds the last known tier with a 5 minute TTL.
type Cache struct {
	mu   sync.RWMutex
	cfg  Config
	tier Tier
}

func NewCache(cfg Config) *Cache { return &Cache{cfg: cfg, tier: Tier{Plan: "local"}} }

// Get returns the cached tier, refreshing in the background when stale.
// Fail-open: any fetch error keeps the previous tier.
func (c *Cache) Get(ctx context.Context) Tier {
	c.mu.RLock()
	tier, stale := c.tier, time.Since(c.tier.FetchedAt) > 5*time.Minute
	c.mu.RUnlock()
	if !stale || !c.cfg.Enabled() {
		return tier
	}
	if fresh, err := c.cfg.FetchTier(ctx); err == nil {
		c.mu.Lock()
		c.tier = fresh
		c.mu.Unlock()
		return fresh
	}
	return tier
}

// FetchTier GETs /v1/entitlements/{org} live.
func (c Config) FetchTier(ctx context.Context) (Tier, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/v1/entitlements/"+c.OrgID, nil)
	if err != nil {
		return Tier{Plan: "local"}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.Client.Do(req)
	if err != nil {
		return Tier{Plan: "local"}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Tier{Plan: "local"}, fmt.Errorf("billing: tier fetch HTTP %d", resp.StatusCode)
	}
	var out Tier
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Tier{Plan: "local"}, err
	}
	if out.Plan == "" {
		out.Plan = "pilot"
	}
	out.FetchedAt = time.Now()
	return out, nil
}

// ReportUsage POSTs a meter delta idempotently.
func (c Config) ReportUsage(ctx context.Context, events int64, key string) error {
	if !c.Enabled() {
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"organization_id": c.OrgID,
		"metrics":         map[string]int64{"events": events},
		"idempotency_key": key,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/usage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("billing: usage HTTP %d", resp.StatusCode)
	}
	return nil
}
