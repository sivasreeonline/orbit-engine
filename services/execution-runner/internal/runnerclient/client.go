package runnerclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/acceptancejournal"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerauth"
)

const (
	claimPath             = "/internal/v1/runner/claim"
	acceptPath            = "/internal/v1/runner/accept"
	startPath             = "/internal/v1/runner/start"
	heartbeatPath         = "/internal/v1/runner/heartbeat"
	artifactPath          = "/internal/v1/runner/artifact"
	completionPath        = "/internal/v1/runner/complete"
	maxResponseBytes      = 64 << 10
	maxArtifactResponseBytes = 8 << 20
	maxArtifactSourceBytes   = 256 << 10
	maxArtifactTestBytes     = 1 << 20
	maxArtifactTestCases     = 200
	maxActiveLeases       = 2
	leaseDurationSeconds  = 120
	defaultRequestTimeout = 10 * time.Second
)

var uuidPattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

type Config struct {
	ControlPlaneURL string
	KeyID           string
	PrivateKey      ed25519.PrivateKey
	HTTPClient      *http.Client
	Now             func() time.Time
	Random          io.Reader
}

type Client struct {
	baseURL    *url.URL
	keyID      string
	privateKey ed25519.PrivateKey
	httpClient *http.Client
	now        func() time.Time
	random     io.Reader
	randomMu   sync.Mutex
}

type Dispatch struct {
	DispatchID      string    `json:"dispatchId"`
	ExecutionID     string    `json:"executionId"`
	AttemptID       string    `json:"attemptId"`
	ProtocolVersion string    `json:"protocolVersion"`
	CorrelationID   string    `json:"correlationId"`
	DeliveryAttempt int       `json:"deliveryAttempt"`
	LeaseToken      string    `json:"leaseToken"`
	LeaseExpiresAt  time.Time `json:"leaseExpiresAt"`
}

type AcceptanceResult struct {
	DispatchID   string
	AcceptanceID string
	EventID      string
	AcceptedAt   time.Time
	Replayed     bool
}

type StartResult struct {
	DispatchID string
	ExecutionID string
	AttemptID string
	EventID string
	StartedAt time.Time
	Replayed bool
}

type HeartbeatResult struct {
	HeartbeatID string
	DispatchID string
	ExecutionID string
	LeaseExpiresAt time.Time
	Replayed bool
}

// CompletionInput contains only the allowlisted aggregate terminal result.
// It deliberately has no fields for source, test contents, stdout or stderr.
type CompletionInput struct {
	InfrastructureStatus string
	InfrastructureErrorCode string
	CompilationStatus string
	Verdict string
	CleanupStatus string
	TestsTotal int64
	TestsPassed int64
	ElapsedMs int64
	PeakMemoryBytes *int64
	RunnerVersion string
	RuntimeImageDigest string
	ResultSHA256 string
	StartedAt time.Time
	CompletedAt time.Time
}

type CompletionResult struct {
	ExecutionID string
	AttemptID string
	State string
	ResultSHA256 string
	Replayed bool
}

type ArtifactTestCase struct {
	TestCaseID string `json:"testCaseId"`
	Sequence int `json:"sequence"`
	Visibility string `json:"visibility"`
	Input string `json:"input"`
	ExpectedOutput string `json:"expectedOutput"`
}

type ExecutionArtifact struct {
	ExecutionID string `json:"executionId"`
	AttemptID string `json:"attemptId"`
	ProblemVersionID string `json:"problemVersionId"`
	ProblemSlug string `json:"problemSlug"`
	ProblemTitle string `json:"problemTitle"`
	Action string `json:"action"`
	Language string `json:"language"`
	RuntimeVersion string `json:"runtimeVersion"`
	SourceArtifactID string `json:"sourceArtifactId"`
	SourceSHA256 string `json:"sourceSha256"`
	SourceCode string `json:"sourceCode"`
	TestBundleID string `json:"testBundleId"`
	TestBundleSHA256 string `json:"testBundleSha256"`
	TestCases []ArtifactTestCase `json:"testCases"`
}

type RemoteError struct {
	StatusCode int
	Code       string
}

func (e *RemoteError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("runner control plane returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("runner control plane returned HTTP %d (%s)", e.StatusCode, e.Code)
}

type claimRequest struct {
	RequestedSlots int `json:"requestedSlots"`
}

type claimResponse struct {
	Data []Dispatch `json:"data"`
	Meta struct {
		Claimed                    int `json:"claimed"`
		MaxActiveLeasesPerRunner   int `json:"maxActiveLeasesPerRunner"`
		LeaseDurationSeconds       int `json:"leaseDurationSeconds"`
	} `json:"meta"`
}

type acceptanceRequest struct {
	AcceptanceID string `json:"acceptanceId"`
	DispatchID   string `json:"dispatchId"`
	ExecutionID  string `json:"executionId"`
	AttemptID    string `json:"attemptId"`
	LeaseToken   string `json:"leaseToken"`
}

type acceptanceResponse struct {
	Data struct {
		Accepted     bool   `json:"accepted"`
		Replayed     bool   `json:"replayed"`
		DispatchID   string `json:"dispatchId"`
		AcceptanceID string `json:"acceptanceId"`
		EventID      string `json:"eventId"`
		AcceptedAt   string `json:"acceptedAt"`
	} `json:"data"`
}

type startRequest struct {
	DispatchID string `json:"dispatchId"`
	ExecutionID string `json:"executionId"`
	AttemptID string `json:"attemptId"`
	LeaseToken string `json:"leaseToken"`
}

type startResponse struct {
	Data struct {
		Started bool `json:"started"`
		Replayed bool `json:"replayed"`
		DispatchID string `json:"dispatchId"`
		ExecutionID string `json:"executionId"`
		AttemptID string `json:"attemptId"`
		EventID string `json:"eventId"`
		StartedAt string `json:"startedAt"`
	} `json:"data"`
}

type heartbeatRequest struct {
	HeartbeatID string `json:"heartbeatId"`
	DispatchID string `json:"dispatchId"`
	ExecutionID string `json:"executionId"`
	AttemptID string `json:"attemptId"`
	LeaseToken string `json:"leaseToken"`
}

type heartbeatResponse struct {
	Data struct {
		Renewed bool `json:"renewed"`
		Replayed bool `json:"replayed"`
		HeartbeatID string `json:"heartbeatId"`
		DispatchID string `json:"dispatchId"`
		ExecutionID string `json:"executionId"`
		LeaseExpiresAt string `json:"leaseExpiresAt"`
	} `json:"data"`
}

type artifactRequest struct {
	DispatchID string `json:"dispatchId"`
	ExecutionID string `json:"executionId"`
	AttemptID string `json:"attemptId"`
	LeaseToken string `json:"leaseToken"`
}

type artifactResponse struct {
	Data ExecutionArtifact `json:"data"`
}

type completionRequest struct {
	DispatchID string `json:"dispatchId"`
	ExecutionID string `json:"executionId"`
	AttemptID string `json:"attemptId"`
	LeaseToken string `json:"leaseToken"`
	InfrastructureStatus string `json:"infrastructureStatus"`
	InfrastructureErrorCode string `json:"infrastructureErrorCode,omitempty"`
	CompilationStatus string `json:"compilationStatus"`
	Verdict string `json:"verdict"`
	CleanupStatus string `json:"cleanupStatus"`
	TestsTotal int64 `json:"testsTotal"`
	TestsPassed int64 `json:"testsPassed"`
	ElapsedMs int64 `json:"elapsedMs"`
	PeakMemoryBytes *int64 `json:"peakMemoryBytes,omitempty"`
	RunnerVersion string `json:"runnerVersion"`
	RuntimeImageDigest string `json:"runtimeImageDigest,omitempty"`
	ResultSHA256 string `json:"resultSha256"`
	StartedAt string `json:"startedAt"`
	CompletedAt string `json:"completedAt"`
}

type completionResponse struct {
	Data struct {
		Completed bool `json:"completed"`
		Replayed bool `json:"replayed"`
		ExecutionID string `json:"executionId"`
		AttemptID string `json:"attemptId"`
		State string `json:"state"`
		ResultSHA256 string `json:"resultSha256"`
	} `json:"data"`
}

type errorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func New(config Config) (*Client, error) {
	if !regexp.MustCompile("^[A-Za-z0-9._:-]{1,128}$").MatchString(config.KeyID) {
		return nil, errors.New("runner key ID is invalid")
	}
	if len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("runner Ed25519 private key is invalid")
	}

	baseURL, err := url.Parse(strings.TrimSpace(config.ControlPlaneURL))
	if err != nil || baseURL == nil || baseURL.Host == "" ||
		baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" ||
		(baseURL.Path != "" && baseURL.Path != "/") {
		return nil, errors.New("control-plane URL must be an origin without credentials, path, query or fragment")
	}
	if baseURL.Scheme != "https" {
		if baseURL.Scheme != "http" || !isLoopbackHost(baseURL.Hostname()) {
			return nil, errors.New("control-plane URL must use HTTPS; HTTP is allowed only for loopback development")
		}
	}

	httpClient := &http.Client{
		Timeout: defaultRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	if config.HTTPClient != nil {
		copyOfClient := *config.HTTPClient
		httpClient = &copyOfClient
		if httpClient.Timeout == 0 {
			httpClient.Timeout = defaultRequestTimeout
		}
	}
	// Signed runner requests must never be redirected to a different origin.
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}

	return &Client{
		baseURL:    baseURL,
		keyID:      config.KeyID,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...),
		httpClient: httpClient,
		now:        now,
		random:     random,
	}, nil
}

// Claim requests a bounded batch of metadata-only dispatch leases. The control
// plane remains authoritative for fairness and the two-active-lease runner cap.
func (c *Client) Claim(ctx context.Context, requestedSlots int) ([]Dispatch, error) {
	if requestedSlots < 1 || requestedSlots > 4 {
		return nil, errors.New("requested slots must be between 1 and 4")
	}

	body, err := json.Marshal(claimRequest{RequestedSlots: requestedSlots})
	if err != nil {
		return nil, fmt.Errorf("encode runner claim: %w", err)
	}
	var response claimResponse
	if err := c.postSignedJSON(ctx, claimPath, body, &response); err != nil {
		return nil, err
	}

	if response.Meta.Claimed != len(response.Data) ||
		response.Meta.Claimed < 0 ||
		response.Meta.Claimed > requestedSlots ||
		response.Meta.Claimed > maxActiveLeases ||
		response.Meta.MaxActiveLeasesPerRunner != maxActiveLeases ||
		response.Meta.LeaseDurationSeconds != leaseDurationSeconds {
		return nil, errors.New("runner claim response violates the bounded lease contract")
	}

	seen := make(map[string]struct{}, len(response.Data))
	now := c.now().UTC()
	for _, dispatch := range response.Data {
		if !validDispatch(dispatch) || !dispatch.LeaseExpiresAt.After(now) {
			return nil, errors.New("runner claim response contains an invalid or expired dispatch")
		}
		if _, exists := seen[dispatch.DispatchID]; exists {
			return nil, errors.New("runner claim response contains a duplicate dispatch")
		}
		seen[dispatch.DispatchID] = struct{}{}
	}
	return response.Data, nil
}

// AcceptDispatch first fsyncs the acceptance intent to the local journal and
// only then submits the signed receipt to the control plane.
func (c *Client) AcceptDispatch(
	ctx context.Context,
	journal *acceptancejournal.Journal,
	dispatch Dispatch,
) (AcceptanceResult, error) {
	if journal == nil || !validDispatch(dispatch) {
		return AcceptanceResult{}, errors.New("journal and valid dispatch are required")
	}

	receipt, found, err := journal.Find(dispatch.DispatchID, dispatch.LeaseToken)
	if err != nil {
		return AcceptanceResult{}, fmt.Errorf("find local acceptance receipt: %w", err)
	}
	if found {
		abandoned, err := journal.IsAbandoned(receipt.AcceptanceID)
		if err != nil {
			return AcceptanceResult{}, fmt.Errorf("inspect acceptance receipt abandonment: %w", err)
		}
		if abandoned {
			return AcceptanceResult{}, acceptancejournal.ErrAbandoned
		}
	}
	if !found {
		acceptanceID, err := c.newUUID()
		if err != nil {
			return AcceptanceResult{}, fmt.Errorf("create acceptance ID: %w", err)
		}
		receipt = acceptancejournal.Receipt{
			AcceptanceID: acceptanceID,
			DispatchID:   dispatch.DispatchID,
			ExecutionID:  dispatch.ExecutionID,
			AttemptID:    dispatch.AttemptID,
			LeaseToken:   dispatch.LeaseToken,
			PreparedAt:   c.now().UTC(),
		}
		if _, err := journal.Prepare(receipt); err != nil {
			return AcceptanceResult{}, fmt.Errorf("persist acceptance before send: %w", err)
		}
	}

	return c.acceptPrepared(ctx, journal, receipt)
}

// RetryPending resends every prepared but unconfirmed receipt with a fresh
// timestamp and nonce. The acceptance ID and signed body remain stable.
func (c *Client) RetryPending(
	ctx context.Context,
	journal *acceptancejournal.Journal,
) ([]AcceptanceResult, error) {
	if journal == nil {
		return nil, errors.New("acceptance journal is required")
	}
	pending, err := journal.Pending()
	if err != nil {
		return nil, fmt.Errorf("read pending acceptance receipts: %w", err)
	}
	results := make([]AcceptanceResult, 0, len(pending))
	for _, receipt := range pending {
		result, err := c.acceptPrepared(ctx, journal, receipt)
		if err != nil {
			if isStaleAcceptanceLeaseError(err) {
				// The server has definitively fenced this lease generation. Its
				// receipt remains in the journal, but it must not block newer work.
				continue
			}
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (c *Client) acceptPrepared(
	ctx context.Context,
	journal *acceptancejournal.Journal,
	receipt acceptancejournal.Receipt,
) (AcceptanceResult, error) {
	body, err := json.Marshal(acceptanceRequest{
		AcceptanceID: receipt.AcceptanceID,
		DispatchID:   receipt.DispatchID,
		ExecutionID:  receipt.ExecutionID,
		AttemptID:    receipt.AttemptID,
		LeaseToken:   receipt.LeaseToken,
	})
	if err != nil {
		return AcceptanceResult{}, fmt.Errorf("encode runner acceptance: %w", err)
	}

	var response acceptanceResponse
	if err := c.postSignedJSON(ctx, acceptPath, body, &response); err != nil {
		if isStaleAcceptanceLeaseError(err) {
			if _, abandonErr := journal.Abandon(
				receipt.AcceptanceID,
				"RUNNER_LEASE_STALE",
				c.now().UTC(),
			); abandonErr != nil {
				return AcceptanceResult{}, fmt.Errorf("persist stale acceptance abandonment: %w", abandonErr)
			}
		}
		return AcceptanceResult{}, err
	}
	if !response.Data.Accepted ||
		response.Data.DispatchID != receipt.DispatchID ||
		response.Data.AcceptanceID != receipt.AcceptanceID ||
		!uuidPattern.MatchString(response.Data.EventID) {
		return AcceptanceResult{}, errors.New("runner acceptance response does not match the prepared receipt")
	}
	acceptedAt, err := time.Parse(time.RFC3339Nano, response.Data.AcceptedAt)
	if err != nil {
		return AcceptanceResult{}, errors.New("runner acceptance response has an invalid timestamp")
	}
	if _, err := journal.Confirm(receipt.AcceptanceID, response.Data.EventID, acceptedAt); err != nil {
		return AcceptanceResult{}, fmt.Errorf("persist acceptance confirmation: %w", err)
	}
	return AcceptanceResult{
		DispatchID:   receipt.DispatchID,
		AcceptanceID: receipt.AcceptanceID,
		EventID:      response.Data.EventID,
		AcceptedAt:   acceptedAt.UTC(),
		Replayed:     response.Data.Replayed,
	}, nil
}

// StartDispatch durably transitions an accepted lease to RUNNING. The operation
// is idempotent for the same dispatch and fencing token, so callers may safely
// retry after a lost acknowledgement.
func isStaleAcceptanceLeaseError(err error) bool {
	var remote *RemoteError
	return errors.As(err, &remote) &&
		remote.StatusCode == http.StatusConflict &&
		remote.Code == "RUNNER_LEASE_STALE"
}

func (c *Client) StartDispatch(ctx context.Context, dispatch Dispatch) (StartResult, error) {
	if !validDispatch(dispatch) {
		return StartResult{}, errors.New("valid dispatch is required")
	}
	body, err := json.Marshal(startRequest{
		DispatchID: dispatch.DispatchID,
		ExecutionID: dispatch.ExecutionID,
		AttemptID: dispatch.AttemptID,
		LeaseToken: dispatch.LeaseToken,
	})
	if err != nil {
		return StartResult{}, fmt.Errorf("encode runner start: %w", err)
	}
	var response startResponse
	if err := c.postSignedJSON(ctx, startPath, body, &response); err != nil {
		return StartResult{}, err
	}
	data := response.Data
	if !data.Started || data.DispatchID != dispatch.DispatchID ||
		data.ExecutionID != dispatch.ExecutionID || data.AttemptID != dispatch.AttemptID ||
		!uuidPattern.MatchString(data.EventID) {
		return StartResult{}, errors.New("runner start response does not match the dispatch")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, data.StartedAt)
	if err != nil {
		return StartResult{}, errors.New("runner start response has an invalid timestamp")
	}
	return StartResult{
		DispatchID: data.DispatchID,
		ExecutionID: data.ExecutionID,
		AttemptID: data.AttemptID,
		EventID: data.EventID,
		StartedAt: startedAt.UTC(),
		Replayed: data.Replayed,
	}, nil
}

// NewHeartbeatID creates an idempotency key for one lease renewal. Keep this
// identifier and reuse it if the acknowledgement is lost; use a new ID only
// for the next scheduled renewal.
func (c *Client) NewHeartbeatID() (string, error) {
	return c.newUUID()
}

// RenewLease renews the dispatch and execution-job lease together. Reuse the
// same heartbeatID when retrying the same logical heartbeat after a timeout.
func (c *Client) RenewLease(
	ctx context.Context,
	dispatch Dispatch,
	heartbeatID string,
) (HeartbeatResult, error) {
	if !validDispatch(dispatch) || !uuidPattern.MatchString(heartbeatID) {
		return HeartbeatResult{}, errors.New("valid dispatch and heartbeat ID are required")
	}
	body, err := json.Marshal(heartbeatRequest{
		HeartbeatID: heartbeatID,
		DispatchID: dispatch.DispatchID,
		ExecutionID: dispatch.ExecutionID,
		AttemptID: dispatch.AttemptID,
		LeaseToken: dispatch.LeaseToken,
	})
	if err != nil {
		return HeartbeatResult{}, fmt.Errorf("encode runner heartbeat: %w", err)
	}
	var response heartbeatResponse
	if err := c.postSignedJSON(ctx, heartbeatPath, body, &response); err != nil {
		return HeartbeatResult{}, err
	}
	data := response.Data
	if !data.Renewed || data.HeartbeatID != heartbeatID ||
		data.DispatchID != dispatch.DispatchID || data.ExecutionID != dispatch.ExecutionID {
		return HeartbeatResult{}, errors.New("runner heartbeat response does not match the lease")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, data.LeaseExpiresAt)
	if err != nil || !expiresAt.After(c.now()) {
		return HeartbeatResult{}, errors.New("runner heartbeat response has an invalid or expired lease timestamp")
	}
	if expiresAt.After(c.now().Add(3 * time.Minute)) {
		return HeartbeatResult{}, errors.New("runner heartbeat response exceeds the bounded renewal horizon")
	}
	return HeartbeatResult{
		HeartbeatID: data.HeartbeatID,
		DispatchID: data.DispatchID,
		ExecutionID: data.ExecutionID,
		LeaseExpiresAt: expiresAt.UTC(),
		Replayed: data.Replayed,
	}, nil
}

// FetchArtifact retrieves source and the action-scoped test bundle only after
// the control plane confirms this runner's accepted, started and active lease.
// The method independently verifies all source and test-bundle integrity data.
func (c *Client) FetchArtifact(
	ctx context.Context,
	dispatch Dispatch,
) (ExecutionArtifact, error) {
	if !validDispatch(dispatch) || !dispatch.LeaseExpiresAt.After(c.now()) {
		return ExecutionArtifact{}, errors.New("valid unexpired dispatch is required")
	}
	body, err := json.Marshal(artifactRequest{
		DispatchID: dispatch.DispatchID,
		ExecutionID: dispatch.ExecutionID,
		AttemptID: dispatch.AttemptID,
		LeaseToken: dispatch.LeaseToken,
	})
	if err != nil {
		return ExecutionArtifact{}, fmt.Errorf("encode runner artifact request: %w", err)
	}
	var response artifactResponse
	if err := c.postSignedJSONWithLimit(ctx, artifactPath, body, &response, maxArtifactResponseBytes); err != nil {
		return ExecutionArtifact{}, err
	}
	artifact := response.Data
	if err := validateArtifact(dispatch, artifact); err != nil {
		return ExecutionArtifact{}, err
	}
	return artifact, nil
}

// CompleteExecution submits an allowlisted aggregate result for an already
// started dispatch. The control plane binds it to the authenticated runner
// and exact lease. Repeating the same input after a lost acknowledgement is
// safe: the server returns the existing completion receipt.
func (c *Client) CompleteExecution(
	ctx context.Context,
	dispatch Dispatch,
	result CompletionInput,
) (CompletionResult, error) {
	if !validDispatch(dispatch) {
		return CompletionResult{}, errors.New("valid dispatch is required")
	}
	if err := validateCompletionInput(result); err != nil {
		return CompletionResult{}, err
	}

	body, err := json.Marshal(completionRequest{
		DispatchID: dispatch.DispatchID,
		ExecutionID: dispatch.ExecutionID,
		AttemptID: dispatch.AttemptID,
		LeaseToken: dispatch.LeaseToken,
		InfrastructureStatus: result.InfrastructureStatus,
		InfrastructureErrorCode: result.InfrastructureErrorCode,
		CompilationStatus: result.CompilationStatus,
		Verdict: result.Verdict,
		CleanupStatus: result.CleanupStatus,
		TestsTotal: result.TestsTotal,
		TestsPassed: result.TestsPassed,
		ElapsedMs: result.ElapsedMs,
		PeakMemoryBytes: result.PeakMemoryBytes,
		RunnerVersion: result.RunnerVersion,
		RuntimeImageDigest: result.RuntimeImageDigest,
		ResultSHA256: result.ResultSHA256,
		StartedAt: result.StartedAt.UTC().Format(time.RFC3339Nano),
		CompletedAt: result.CompletedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return CompletionResult{}, fmt.Errorf("encode runner completion: %w", err)
	}

	var response completionResponse
	if err := c.postSignedJSON(ctx, completionPath, body, &response); err != nil {
		return CompletionResult{}, err
	}
	data := response.Data
	expectedState := "COMPLETED"
	if result.InfrastructureStatus == "FAILED" {
		expectedState = "FAILED_INFRASTRUCTURE"
	}
	if !data.Completed || data.ExecutionID != dispatch.ExecutionID ||
		data.AttemptID != dispatch.AttemptID ||
		data.State != expectedState || data.ResultSHA256 != result.ResultSHA256 {
		return CompletionResult{}, errors.New("runner completion acknowledgement does not match the submitted result")
	}
	return CompletionResult{
		ExecutionID: data.ExecutionID,
		AttemptID: data.AttemptID,
		State: data.State,
		ResultSHA256: data.ResultSHA256,
		Replayed: data.Replayed,
	}, nil
}

func validateCompletionInput(result CompletionInput) error {
	if result.InfrastructureStatus != "SUCCEEDED" && result.InfrastructureStatus != "FAILED" {
		return errors.New("invalid runner completion infrastructure status")
	}
	if result.CompilationStatus != "NOT_STARTED" &&
		result.CompilationStatus != "SUCCEEDED" &&
		result.CompilationStatus != "FAILED" {
		return errors.New("invalid runner completion compilation status")
	}
	allowedVerdicts := map[string]bool{
		"NOT_EVALUATED": true,
		"ACCEPTED": true,
		"WRONG_ANSWER": true,
		"COMPILATION_ERROR": true,
		"RUNTIME_ERROR": true,
		"TIME_LIMIT_EXCEEDED": true,
		"MEMORY_LIMIT_EXCEEDED": true,
		"OUTPUT_LIMIT_EXCEEDED": true,
		"INTERNAL_ERROR": true,
	}
	if !allowedVerdicts[result.Verdict] {
		return errors.New("invalid runner completion verdict")
	}
	if result.CleanupStatus != "SUCCEEDED" &&
		result.CleanupStatus != "FAILED" &&
		result.CleanupStatus != "UNKNOWN" {
		return errors.New("invalid runner completion cleanup status")
	}
	if result.InfrastructureStatus == "FAILED" {
		if !regexp.MustCompile("^[A-Z][A-Z0-9_]{0,63}$").MatchString(result.InfrastructureErrorCode) ||
			result.Verdict != "NOT_EVALUATED" {
			return errors.New("infrastructure failure requires a safe error code and NOT_EVALUATED verdict")
		}
	} else if result.InfrastructureErrorCode != "" || result.Verdict == "NOT_EVALUATED" {
		return errors.New("successful infrastructure result cannot include an infrastructure error code")
	}
	if result.CompilationStatus == "FAILED" && result.Verdict != "COMPILATION_ERROR" {
		return errors.New("failed compilation requires COMPILATION_ERROR verdict")
	}
	if result.CompilationStatus != "FAILED" && result.Verdict == "COMPILATION_ERROR" {
		return errors.New("COMPILATION_ERROR verdict requires failed compilation")
	}
	if result.TestsTotal < 0 || result.TestsPassed < 0 || result.TestsPassed > result.TestsTotal ||
		result.TestsTotal > 9_007_199_254_740_991 || result.TestsPassed > 9_007_199_254_740_991 ||
		result.ElapsedMs < 0 || result.ElapsedMs > 9_007_199_254_740_991 {
		return errors.New("runner completion counts or duration are outside the safe integer range")
	}
	if result.CompilationStatus == "FAILED" && result.TestsTotal != 0 {
		return errors.New("failed compilation cannot contain test results")
	}
	if result.Verdict == "ACCEPTED" && (result.TestsTotal == 0 || result.TestsPassed != result.TestsTotal) {
		return errors.New("ACCEPTED verdict requires all non-empty test cases to pass")
	}
	if result.PeakMemoryBytes != nil &&
		(*result.PeakMemoryBytes < 0 || *result.PeakMemoryBytes > 9_007_199_254_740_991) {
		return errors.New("runner completion peak memory is outside the safe integer range")
	}
	if !regexp.MustCompile("^[A-Za-z0-9._+-]{1,64}$").MatchString(result.RunnerVersion) {
		return errors.New("invalid runner completion version")
	}
	if result.RuntimeImageDigest != "" && !isSHA256(result.RuntimeImageDigest) {
		return errors.New("invalid runner completion runtime image digest")
	}
	if !isSHA256(result.ResultSHA256) {
		return errors.New("invalid runner completion result digest")
	}
	if result.StartedAt.IsZero() || result.CompletedAt.IsZero() ||
		result.CompletedAt.Before(result.StartedAt) {
		return errors.New("invalid runner completion time range")
	}
	return nil
}

func validateArtifact(dispatch Dispatch, artifact ExecutionArtifact) error {
	if artifact.ExecutionID != dispatch.ExecutionID ||
		artifact.AttemptID != dispatch.AttemptID ||
		!uuidPattern.MatchString(artifact.ProblemVersionID) ||
		!regexp.MustCompile("^[a-z0-9]+(?:-[a-z0-9]+)*$").MatchString(artifact.ProblemSlug) ||
		len(artifact.ProblemSlug) > 64 ||
		strings.TrimSpace(artifact.ProblemTitle) == "" || len(artifact.ProblemTitle) > 160 {
		return errors.New("runner artifact identity or problem metadata is invalid")
	}
	if artifact.Action != "RUN" && artifact.Action != "SUBMIT" {
		return errors.New("runner artifact action is invalid")
	}
	if artifact.Language != "java" && artifact.Language != "python" {
		return errors.New("runner artifact language is invalid")
	}
	if artifact.RuntimeVersion == "" || len(artifact.RuntimeVersion) > 32 ||
		strings.TrimSpace(artifact.RuntimeVersion) != artifact.RuntimeVersion ||
		!uuidPattern.MatchString(artifact.SourceArtifactID) {
		return errors.New("runner artifact runtime or source identity is invalid")
	}
	if !isSHA256(artifact.SourceSHA256) || !isSHA256(artifact.TestBundleSHA256) {
		return errors.New("runner artifact digest is invalid")
	}
	sourceBytes := []byte(artifact.SourceCode)
	if !utf8.Valid(sourceBytes) || len(sourceBytes) > maxArtifactSourceBytes {
		return errors.New("runner artifact source is invalid or exceeds its size limit")
	}
	sourceDigest := sha256.Sum256(sourceBytes)
	if hex.EncodeToString(sourceDigest[:]) != artifact.SourceSHA256 {
		return errors.New("runner artifact source hash mismatch")
	}
	if len(artifact.TestCases) < 1 || len(artifact.TestCases) > maxArtifactTestCases {
		return errors.New("runner artifact test case count is invalid")
	}
	lastSequence := 0
	totalTestBytes := 0
	for _, testCase := range artifact.TestCases {
		if !uuidPattern.MatchString(testCase.TestCaseID) ||
			testCase.Sequence <= lastSequence ||
			(testCase.Visibility != "PUBLIC" && testCase.Visibility != "HIDDEN") {
			return errors.New("runner artifact contains an invalid or unordered test case")
		}
		if artifact.Action == "RUN" && testCase.Visibility != "PUBLIC" {
			return errors.New("RUN artifact must not contain hidden test cases")
		}
		if !utf8.ValidString(testCase.Input) || !utf8.ValidString(testCase.ExpectedOutput) {
			return errors.New("runner artifact test case contains invalid UTF-8")
		}
		totalTestBytes += len([]byte(testCase.Input)) + len([]byte(testCase.ExpectedOutput))
		if totalTestBytes > maxArtifactTestBytes {
			return errors.New("runner artifact test bundle exceeds its size limit")
		}
		lastSequence = testCase.Sequence
	}
	bundleDigest := sha256.Sum256(canonicalTestBundleBytes(artifact.TestCases))
	bundleHash := hex.EncodeToString(bundleDigest[:])
	if bundleHash != artifact.TestBundleSHA256 {
		return errors.New("runner artifact test bundle hash mismatch")
	}
	expectedBundleID := artifact.ProblemVersionID + "-" + strings.ToLower(artifact.Action) + "-" + bundleHash[:16]
	if artifact.TestBundleID != expectedBundleID {
		return errors.New("runner artifact test bundle ID does not match its digest")
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func appendLengthPrefixed(target *bytes.Buffer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	target.Write(length[:])
	target.Write(value)
}

// canonicalTestBundleBytes mirrors the versioned API encoding: length-prefixed
// magic and case IDs, big-endian u32 sequence/count, visibility byte 1=PUBLIC
// or 2=HIDDEN, then length-prefixed UTF-8 input and expected output.
func canonicalTestBundleBytes(testCases []ArtifactTestCase) []byte {
	var buffer bytes.Buffer
	appendLengthPrefixed(&buffer, []byte("SKYHIGH-TEST-BUNDLE-V1"))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(testCases)))
	buffer.Write(count[:])
	for _, testCase := range testCases {
		appendLengthPrefixed(&buffer, []byte(testCase.TestCaseID))
		var sequence [4]byte
		binary.BigEndian.PutUint32(sequence[:], uint32(testCase.Sequence))
		buffer.Write(sequence[:])
		if testCase.Visibility == "PUBLIC" {
			buffer.WriteByte(1)
		} else {
			buffer.WriteByte(2)
		}
		appendLengthPrefixed(&buffer, []byte(testCase.Input))
		appendLengthPrefixed(&buffer, []byte(testCase.ExpectedOutput))
	}
	return buffer.Bytes()
}

func (c *Client) postSignedJSON(ctx context.Context, path string, body []byte, output any) error {
	return c.postSignedJSONWithLimit(ctx, path, body, output, maxResponseBytes)
}

func (c *Client) postSignedJSONWithLimit(ctx context.Context, path string, body []byte, output any, responseLimit int64) error {
	nonceBytes, err := c.randomBytes(32)
	if err != nil {
		return fmt.Errorf("create signed request nonce: %w", err)
	}
	timestamp := strconv.FormatInt(c.now().UTC().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	signed := runnerauth.SignedRequest{
		KeyID: c.keyID, Method: http.MethodPost, Path: path,
		Timestamp: timestamp, Nonce: nonce, Body: body,
	}
	signature, err := runnerauth.SignRequest(c.privateKey, signed)
	if err != nil {
		return fmt.Errorf("sign runner request: %w", err)
	}

	endpoint := *c.baseURL
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create runner request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-SkyHigh-Runner-Key-Id", c.keyID)
	request.Header.Set("X-SkyHigh-Runner-Timestamp", timestamp)
	request.Header.Set("X-SkyHigh-Runner-Nonce", nonce)
	request.Header.Set("X-SkyHigh-Runner-Signature", signature)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send runner request: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		return fmt.Errorf("read runner response: %w", err)
	}
	if int64(len(responseBody)) > responseLimit {
		return errors.New("runner response exceeds the configured size limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var apiError errorResponse
		_ = json.Unmarshal(responseBody, &apiError)
		return &RemoteError{StatusCode: response.StatusCode, Code: apiError.Error.Code}
	}
	if err := decodeStrict(responseBody, output); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	return nil
}

func decodeStrict(body []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("runner response contains trailing JSON")
		}
		return err
	}
	return nil
}

func validDispatch(dispatch Dispatch) bool {
	return uuidPattern.MatchString(dispatch.DispatchID) &&
		uuidPattern.MatchString(dispatch.ExecutionID) &&
		uuidPattern.MatchString(dispatch.AttemptID) &&
		uuidPattern.MatchString(dispatch.LeaseToken) &&
		dispatch.ProtocolVersion != "" && len(dispatch.ProtocolVersion) <= 64 &&
		dispatch.CorrelationID != "" && len(dispatch.CorrelationID) <= 128 &&
		dispatch.DeliveryAttempt >= 1 && !dispatch.LeaseExpiresAt.IsZero()
}

func (c *Client) newUUID() (string, error) {
	value, err := c.randomBytes(16)
	if err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" +
		encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func (c *Client) randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	c.randomMu.Lock()
	defer c.randomMu.Unlock()
	if _, err := io.ReadFull(c.random, value); err != nil {
		return nil, err
	}
	return value, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
