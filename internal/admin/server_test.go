// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizeRejectsBadBearer(t *testing.T) {
	server := &Server{AdminToken: "secret"}
	handler := server.authorize(server.AdminToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestAuthorizeAcceptsMatchingBearer(t *testing.T) {
	server := &Server{AdminToken: "secret"}
	handler := server.authorize(server.AdminToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code=%d", rec.Code)
	}
}
