// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package delivery

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/laststate/relay/internal/ingest"
	"github.com/laststate/relay/internal/store"
	"github.com/laststate/relay/internal/traceapi"
)

func TestDeliveryPersistsThenPostsIdempotently(t *testing.T) {
	var received string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/relay/capabilities":
			http.NotFound(writer, request)
			return
		case "/v1/ingest":
			received = request.Header.Get("Idempotency-Key")
			writer.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("path = %s", request.URL.Path)
		}
	}))
	defer server.Close()

	relay, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	if err := relay.ConfigureDestinations(context.Background(), []store.Destination{{ID: "trace", URL: server.URL}}, "mirror"); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString("4c5354500102000007000000090000000600000074ddc48901000200aabbea84ccd8")
	if err != nil {
		t.Fatal(err)
	}
	result, err := (ingest.Service{Store: relay}).Accept(context.Background(), "test", raw)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{Store: relay, Client: server.Client(), Concurrency: 1, MinDelay: time.Millisecond}
	if err := worker.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := relay.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if received != result.Event.ID || status.Delivered != 1 || status.Pending != 0 {
		t.Fatalf("received=%q status=%+v", received, status)
	}
}

func TestBatchDeliveryUsesNegotiatedEndpoint(t *testing.T) {
	var batchCount int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/relay/capabilities":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"api_version":"1","lep_versions":[1],"max_event_size":4194304,"max_batch_events":10,"max_batch_bytes":4194304,"batch_ingest":true}`))
		case "/v1/events:batch":
			var requestBody traceapi.BatchRequest
			if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
				t.Errorf("decode batch: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			batchCount = len(requestBody.Events)
			response := traceapi.BatchResponse{}
			for _, event := range requestBody.Events {
				response.Accepted = append(response.Accepted, traceapi.AcceptedEvent{EventID: event.EventID, Receipt: "stored"})
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(response)
		default:
			t.Errorf("unexpected path = %s", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	relay, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	if err := relay.ConfigureDestinations(context.Background(), []store.Destination{{ID: "trace", URL: server.URL}}, "mirror"); err != nil {
		t.Fatal(err)
	}
	for index := uint32(1); index <= 2; index++ {
		raw := batchTestEnvelope(index)
		if _, err := (ingest.Service{Store: relay}).Accept(context.Background(), "test", raw); err != nil {
			t.Fatal(err)
		}
	}
	worker := &Worker{
		Store: relay,
		Destinations: map[string]RuntimeDestination{
			"trace": {Client: server.Client(), BatchEnabled: true, MaxBatchEvents: 10, MaxBatchBytes: 4 << 20},
		},
		Concurrency: 1,
		MinDelay:    time.Millisecond,
	}
	if err := worker.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := relay.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if batchCount != 2 || status.Delivered != 2 || status.Pending != 0 {
		t.Fatalf("batchCount=%d status=%+v", batchCount, status)
	}
}

func batchTestEnvelope(sequence uint32) []byte {
	payload := []byte{1, 0, 1, 0, byte(sequence)}
	raw := make([]byte, 24+len(payload)+4)
	copy(raw, "LSTP")
	raw[4], raw[5] = 1, 2
	binary.LittleEndian.PutUint32(raw[8:12], sequence)
	binary.LittleEndian.PutUint32(raw[12:16], sequence)
	binary.LittleEndian.PutUint32(raw[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(raw[20:24], crc32.ChecksumIEEE(raw[:20]))
	copy(raw[24:], payload)
	binary.LittleEndian.PutUint32(raw[24+len(payload):], crc32.ChecksumIEEE(payload))
	return raw
}
