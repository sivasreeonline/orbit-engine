package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func validV2JSON(deadline time.Time) []byte {
	return []byte(fmt.Sprintf(`{
		"protocolVersion":"v2",
		"correlationId":"10000000-0000-4000-8000-000000000001",
		"executionId":"20000000-0000-4000-8000-000000000001",
		"attemptId":"30000000-0000-4000-8000-000000000001",
		"problemVersionId":"40000000-0000-4000-8000-000000000001",
		"action":"RUN",
		"language":"java",
		"runtimeVersion":"25",
		"runtimeImageDigest":"sha256:%s",
		"sourceArtifactId":"50000000-0000-4000-8000-000000000001",
		"sourceSha256":"%s",
		"testBundleId":"40000000-0000-4000-8000-000000000001-run-%s",
		"comparisonPolicy":"EXACT_BYTES",
		"deadlineAt":"%s",
		"cancellationRef":"cxl_%s",
		"limits":{"cpuQuotaMillis":1000,"memoryBytes":134217728,"wallTimeMillis":5000,"processLimit":16,"outputBytes":65536,"scratchBytes":1048576,"scratchInodes":128}
	}`,
		strings.Repeat("a", 64), strings.Repeat("b", 64),
		strings.Repeat("c", 16), deadline.Format(time.RFC3339Nano), strings.Repeat("d", 32)))
}

func TestDecodeV2RequestVerifiesExactBytesAndStrictContract(t *testing.T) {
	now := time.Now().UTC()
	raw := validV2JSON(now.Add(2 * time.Minute))
	sum := sha256.Sum256(raw)
	request, err := DecodeV2Request(raw, hex.EncodeToString(sum[:]), now)
	if err != nil {
		t.Fatalf("DecodeV2Request() error = %v", err)
	}
	if request.ProtocolVersion != "v2" || request.Action != ActionRun ||
		request.Limits.ScratchInodes != 128 {
		t.Fatalf("decoded request does not match fixture: %#v", request)
	}
}

func TestDecodeV2RequestRejectsDigestMismatch(t *testing.T) {
	raw := validV2JSON(time.Now().UTC().Add(time.Minute))
	_, err := DecodeV2Request(raw, strings.Repeat("0", 64), time.Now().UTC())
	if !errors.Is(err, ErrInvalidV2Request) {
		t.Fatalf("error = %v, want ErrInvalidV2Request", err)
	}
}

func TestDecodeV2RequestRejectsUnknownAndDuplicateFields(t *testing.T) {
	now := time.Now().UTC()
	valid := string(validV2JSON(now.Add(time.Minute)))
	cases := map[string]string{
		"unknown top-level field": strings.Replace(valid, `"protocolVersion":"v2",`, `"protocolVersion":"v2","unexpected":true,`, 1),
		"duplicate top-level field": strings.Replace(valid, `"protocolVersion":"v2",`, `"protocolVersion":"v2","protocolVersion":"v2",`, 1),
		"duplicate nested field": strings.Replace(valid, `"scratchInodes":128`, `"scratchInodes":128,"scratchInodes":128`, 1),
		"missing limit": strings.Replace(valid, `,"scratchInodes":128`, "", 1),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(document)
			sum := sha256.Sum256(raw)
			if _, err := DecodeV2Request(raw, hex.EncodeToString(sum[:]), now); !errors.Is(err, ErrInvalidV2Request) {
				t.Fatalf("error = %v, want ErrInvalidV2Request", err)
			}
		})
	}
}

func TestDecodeV2RequestRejectsExpiredAndOverlongDeadline(t *testing.T) {
	now := time.Now().UTC()
	for name, deadline := range map[string]time.Time{
		"expired": now.Add(-time.Second),
		"over ten minutes": now.Add(11 * time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			raw := validV2JSON(deadline)
			sum := sha256.Sum256(raw)
			if _, err := DecodeV2Request(raw, hex.EncodeToString(sum[:]), now); !errors.Is(err, ErrInvalidV2Request) {
				t.Fatalf("error = %v, want ErrInvalidV2Request", err)
			}
		})
	}
}
