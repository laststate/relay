package billing

import (
	"context"
	"testing"
	"time"
)

func TestCacheDefaultsToLocal(t *testing.T) {
	c := NewCache(Config{})
	got := c.Get(context.Background())
	if got.Plan != "local" {
		t.Fatalf("plan = %q, want local", got.Plan)
	}
}

func TestDisabledReportIsNoop(t *testing.T) {
	c := Config{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.ReportUsage(ctx, 10, "k"); err != nil {
		t.Fatalf("disabled report should be nil, got %v", err)
	}
}
