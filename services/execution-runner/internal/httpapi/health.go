package httpapi

import (
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	Status string `json:"status"`
}

type readinessResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("GET /readyz", readinessHandler)
	return mux
}

func healthHandler(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, healthResponse{Status: "ok"})
}

func readinessHandler(writer http.ResponseWriter, _ *http.Request) {
	// Readiness remains false until a reviewed sandbox executor is installed.
	writeJSON(writer, http.StatusServiceUnavailable, readinessResponse{
		Status: "not_ready",
		Reason: "sandbox_executor_not_configured",
	})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)

	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		// The response may already be committed. Do not write internal details.
		return
	}
}
