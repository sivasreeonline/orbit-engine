package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	NewMux().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}

	var payload healthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("status body = %q, want ok", payload.Status)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("expected Cache-Control: no-store")
	}
}

func TestReadinessRemainsDisabledWithoutSandbox(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	NewMux().ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	var payload readinessResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if payload.Status != "not_ready" {
		t.Fatalf("status body = %q, want not_ready", payload.Status)
	}
	if payload.Reason != "sandbox_executor_not_configured" {
		t.Fatalf("reason = %q, want sandbox_executor_not_configured", payload.Reason)
	}
}
