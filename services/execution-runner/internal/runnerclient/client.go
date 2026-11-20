package runnerclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/acceptancejournal"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerauth"
)

const (
	claimPath             = "/internal/v1/runner/claim"
	acceptPath            = "/internal/v1/runner/accept"
	maxResponseBytes      = 64 << 10
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

func (c *Client) postSignedJSON(ctx context.Context, path string, body []byte, output any) error {
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

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read runner response: %w", err)
	}
	if len(responseBody) > maxResponseBytes {
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
