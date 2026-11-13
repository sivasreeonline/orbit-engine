package runnerclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/acceptancejournal"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerauth"
)

func testClientKey() ed25519.PrivateKey {
	seed := bytes.Repeat([]byte{0x27}, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

func fixedRunnerTime() time.Time {
	return time.Date(2026, 11, 13, 5, 0, 0, 0, time.UTC)
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := New(Config{
		ControlPlaneURL: server.URL,
		KeyID:           "runner-test-key",
		PrivateKey:      testClientKey(),
		HTTPClient:      server.Client(),
		Now:             fixedRunnerTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func verifyTestRequest(t *testing.T, request *http.Request, body []byte) {
	t.Helper()
	signed := runnerauth.SignedRequest{
		KeyID:     request.Header.Get("X-SkyHigh-Runner-Key-Id"),
		Method:    request.Method,
		Path:      request.URL.RequestURI(),
		Timestamp: request.Header.Get("X-SkyHigh-Runner-Timestamp"),
		Nonce:     request.Header.Get("X-SkyHigh-Runner-Nonce"),
		Body:      body,
	}
	if !runnerauth.VerifyRequest(testClientKey().Public().(ed25519.PublicKey), signed,
		request.Header.Get("X-SkyHigh-Runner-Signature")) {
		t.Fatal("request signature did not verify")
	}
	if signed.KeyID != "runner-test-key" || len(signed.Nonce) != 43 {
		t.Fatalf("unexpected signed request identity: %#v", signed)
	}
}

func testDispatch(expiresAt time.Time) Dispatch {
	return Dispatch{
		DispatchID:      "50000000-0000-4000-8000-000000000001",
		ExecutionID:     "60000000-0000-4000-8000-000000000001",
		AttemptID:       "70000000-0000-4000-8000-000000000001",
		ProtocolVersion: "v1",
		CorrelationID:   "corr-600000000000",
		DeliveryAttempt: 1,
		LeaseToken:      "80000000-0000-4000-8000-000000000001",
		LeaseExpiresAt:  expiresAt.UTC(),
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}

func TestClaimSendsSignedBoundedRequestAndValidatesDispatch(t *testing.T) {
	dispatch := testDispatch(fixedRunnerTime().Add(90 * time.Second))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != claimPath {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		verifyTestRequest(t, request, body)
		if string(body) != `{"requestedSlots":2}` {
			t.Fatalf("unexpected claim body: %s", body)
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"data": []Dispatch{dispatch},
			"meta": map[string]int{
				"claimed": 1, "maxActiveLeasesPerRunner": 2, "leaseDurationSeconds": 120,
			},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server)
	claimed, err := client.Claim(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].DispatchID != dispatch.DispatchID {
		t.Fatalf("unexpected claimed dispatches: %#v", claimed)
	}
}

func TestClaimRejectsMalformedAndOutOfContractResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"data":[],"meta":{"claimed":0,"maxActiveLeasesPerRunner":2,"leaseDurationSeconds":120},"sourceCode":"no"}`,
		},
		{
			name: "capacity over cap",
			body: `{"data":[],"meta":{"claimed":0,"maxActiveLeasesPerRunner":3,"leaseDurationSeconds":120}}`,
		},
		{
			name: "claim count mismatch",
			body: `{"data":[],"meta":{"claimed":1,"maxActiveLeasesPerRunner":2,"leaseDurationSeconds":120}}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()
			client := newTestClient(t, server)
			if _, err := client.Claim(context.Background(), 1); err == nil {
				t.Fatal("expected invalid claim response to fail closed")
			}
		})
	}
}

func TestClaimRejectsExpiredDispatch(t *testing.T) {
	dispatch := testDispatch(fixedRunnerTime().Add(-time.Second))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"data": []Dispatch{dispatch},
			"meta": map[string]int{
				"claimed": 1, "maxActiveLeasesPerRunner": 2, "leaseDurationSeconds": 120,
			},
		})
	}))
	defer server.Close()

	if _, err := newTestClient(t, server).Claim(context.Background(), 1); err == nil {
		t.Fatal("expired dispatch was accepted")
	}
}

func TestAcceptDispatchFsyncsBeforeNetworkAndConfirmsAfterAck(t *testing.T) {
	journal, err := acceptancejournal.Open(t.TempDir() + "/acceptance.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	dispatch := testDispatch(fixedRunnerTime().Add(90 * time.Second))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != acceptPath {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		verifyTestRequest(t, request, body)

		pending, err := journal.Pending()
		if err != nil || len(pending) != 1 {
			t.Fatalf("acceptance was sent before durable prepare: pending=%d err=%v", len(pending), err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		expected := []string{"acceptanceId", "dispatchId", "executionId", "attemptId", "leaseToken"}
		if len(payload) != len(expected) {
			t.Fatalf("acceptance body contains unexpected fields: %#v", payload)
		}
		for _, key := range expected {
			if _, exists := payload[key]; !exists {
				t.Fatalf("acceptance body is missing %s", key)
			}
		}
		if _, exists := payload["sourceCode"]; exists {
			t.Fatal("source code must not appear in acceptance receipt")
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"data": map[string]any{
				"accepted": true, "replayed": false,
				"dispatchId": dispatch.DispatchID,
				"acceptanceId": pending[0].AcceptanceID,
				"eventId": "a0000000-0000-4000-8000-000000000001",
				"acceptedAt": fixedRunnerTime().Format(time.RFC3339Nano),
			},
		})
	}))
	defer server.Close()

	result, err := newTestClient(t, server).AcceptDispatch(context.Background(), journal, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	if result.DispatchID != dispatch.DispatchID || result.EventID != "a0000000-0000-4000-8000-000000000001" {
		t.Fatalf("unexpected acceptance result: %#v", result)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("confirmed receipt remains pending: %#v", pending)
	}
}

func TestPendingReceiptSurvivesRestartAndRetriesWithFreshNonce(t *testing.T) {
	path := t.TempDir() + "/acceptance.jsonl"
	journal, err := acceptancejournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := testDispatch(fixedRunnerTime().Add(90 * time.Second))

	var calls atomic.Int32
	var bodies []string
	var nonces []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := make([]byte, request.ContentLength)
		if _, err := request.Body.Read(body); err != nil {
			t.Fatal(err)
		}
		verifyTestRequest(t, request, body)
		mu.Lock()
		bodies = append(bodies, string(body))
		nonces = append(nonces, request.Header.Get("X-SkyHigh-Runner-Nonce"))
		mu.Unlock()

		if calls.Add(1) == 1 {
			writeJSON(t, writer, http.StatusServiceUnavailable, map[string]any{
				"error": map[string]any{
					"code": "RUNNER_CONTROL_PLANE_UNAVAILABLE",
					"message": "retry later", "retryable": true,
				},
				"correlationId": "corr-test",
			})
			return
		}
		var payload acceptanceRequest
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"data": map[string]any{
				"accepted": true, "replayed": true,
				"dispatchId": payload.DispatchID,
				"acceptanceId": payload.AcceptanceID,
				"eventId": "a0000000-0000-4000-8000-000000000002",
				"acceptedAt": fixedRunnerTime().Add(time.Second).Format(time.RFC3339Nano),
			},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server)
	if _, err := client.AcceptDispatch(context.Background(), journal, dispatch); err == nil {
		t.Fatal("expected temporary API failure")
	}
	pending, err := journal.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatalf("receipt not retained after failed request: pending=%d err=%v", len(pending), err)
	}
	firstAcceptanceID := pending[0].AcceptanceID
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, err = acceptancejournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	results, err := client.RetryPending(context.Background(), journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].AcceptanceID != firstAcceptanceID || !results[0].Replayed {
		t.Fatalf("unexpected retry results: %#v", results)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("receipt body changed across retry: %#v", bodies)
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("retry must use a fresh signed nonce: %#v", nonces)
	}
	pending, err = journal.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("retried receipt not confirmed: pending=%d err=%v", len(pending), err)
	}
}

func TestNewRejectsNonLoopbackHTTPAndCredentialedURLs(t *testing.T) {
	key := testClientKey()
	for _, target := range []string{
		"http://example.com",
		"https://user:password@example.com",
		"https://example.com/base/path",
	} {
		_, err := New(Config{ControlPlaneURL: target, KeyID: "key", PrivateKey: key})
		if err == nil {
			t.Fatalf("expected URL %q to be rejected", target)
		}
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"data": []Dispatch{},
			"meta": map[string]int{
				"claimed": 0, "maxActiveLeasesPerRunner": 2, "leaseDurationSeconds": 120,
			},
		})
	}))
	defer destination.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+claimPath, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	_, err := newTestClient(t, redirect).Claim(context.Background(), 1)
	var remoteError *RemoteError
	if !errors.As(err, &remoteError) || remoteError.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect response to be rejected, got %v", err)
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("signed request followed a redirect to another origin")
	}
}

func TestResponseDecoderRejectsTrailingJSON(t *testing.T) {
	var response claimResponse
	err := decodeStrict([]byte(`{"data":[],"meta":{"claimed":0,"maxActiveLeasesPerRunner":2,"leaseDurationSeconds":120}} {}`), &response)
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing JSON to be rejected, got %v", err)
	}
}

func TestRequestBodyIsStableAcrossEncoding(t *testing.T) {
	first, err := json.Marshal(acceptanceRequest{
		AcceptanceID: "90000000-0000-4000-8000-000000000001",
		DispatchID: "50000000-0000-4000-8000-000000000001",
		ExecutionID: "60000000-0000-4000-8000-000000000001",
		AttemptID: "70000000-0000-4000-8000-000000000001",
		LeaseToken: "80000000-0000-4000-8000-000000000001",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(acceptanceRequest{
		AcceptanceID: "90000000-0000-4000-8000-000000000001",
		DispatchID: "50000000-0000-4000-8000-000000000001",
		ExecutionID: "60000000-0000-4000-8000-000000000001",
		AttemptID: "70000000-0000-4000-8000-000000000001",
		LeaseToken: "80000000-0000-4000-8000-000000000001",
	})
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same receipt identity must produce the same signed body")
	}
}
