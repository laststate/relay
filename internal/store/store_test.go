// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package store

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/laststate/relay/internal/lep"
)

func TestPutPersistsAndDeduplicates(t *testing.T) {
	raw, err := hex.DecodeString("4c5354500102000007000000090000000600000074ddc48901000200aabbea84ccd8")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, err := store.Put(context.Background(), "fixture", raw, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate {
		t.Fatal("first event was marked duplicate")
	}
	if _, err := os.Stat(first.Event.RawObjectPath); err != nil {
		t.Fatal(err)
	}
	second, err := store.Put(context.Background(), "fixture", raw, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate || second.Event.ID != first.Event.ID {
		t.Fatalf("unexpected duplicate result: %#v", second)
	}
}
