BEGIN;

-- Proposal-stage schema only. Do not apply in production until the API producer,
-- private artifact endpoint and Go consumer are integrated and policy is approved.
-- These bytes are the authoritative request; retries must never rebuild them
-- from whatever policy happens to be current after a restart.
CREATE TABLE IF NOT EXISTS execution_protocol_requests (
  execution_id uuid PRIMARY KEY
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  protocol_version varchar(16) NOT NULL DEFAULT 'v2'
    CHECK (protocol_version = 'v2'),
  correlation_id uuid NOT NULL,
  intake_at timestamptz NOT NULL,
  deadline_at timestamptz NOT NULL,
  policy_revision varchar(64) NOT NULL
    CHECK (policy_revision ~ '^[A-Za-z0-9._:-]{1,64}$'),
  request_sha256 char(64) NOT NULL
    CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  request_bytes bytea NOT NULL
    CHECK (octet_length(request_bytes) BETWEEN 1 AND 16384),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT execution_protocol_request_deadline_ck CHECK (
    deadline_at > intake_at
    AND deadline_at <= intake_at + interval '10 minutes'
  ),
  CONSTRAINT execution_protocol_request_correlation_uuid_ck CHECK (
    substring(correlation_id::text from 15 for 1) = '4'
    AND substring(correlation_id::text from 20 for 1) IN ('8', '9', 'a', 'b')
  )
);

CREATE INDEX IF NOT EXISTS idx_execution_protocol_requests_deadline
  ON execution_protocol_requests (deadline_at);

CREATE OR REPLACE FUNCTION verify_execution_protocol_request()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_attempt_id uuid;
  request_document jsonb;
  limits_document jsonb;
  request_key_count integer;
  limits_key_count integer;
BEGIN
  SELECT attempt_id
    INTO expected_attempt_id
  FROM execution_jobs
  WHERE id = NEW.execution_id;

  IF NOT FOUND OR expected_attempt_id IS DISTINCT FROM NEW.attempt_id THEN
    RAISE EXCEPTION 'protocol request attempt does not match execution job'
      USING ERRCODE = '23514';
  END IF;

  BEGIN
    request_document := convert_from(NEW.request_bytes, 'UTF8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'protocol request bytes must contain valid UTF-8 JSON'
      USING ERRCODE = '23514';
  END;

  IF jsonb_typeof(request_document) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'protocol v2 request must be a JSON object'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO request_key_count
  FROM jsonb_object_keys(request_document);

  IF request_key_count <> 16
    OR request_document->>'protocolVersion' IS DISTINCT FROM 'v2'
    OR request_document->>'executionId' IS DISTINCT FROM NEW.execution_id::text
    OR request_document->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
    OR request_document->>'correlationId' IS DISTINCT FROM NEW.correlation_id::text
    OR COALESCE(request_document->>'deadlineAt', '') !~ 'Z$'
    OR (request_document->>'deadlineAt')::timestamptz IS DISTINCT FROM NEW.deadline_at
    OR request_document->>'comparisonPolicy' IS DISTINCT FROM 'EXACT_BYTES'
    OR COALESCE(request_document->>'runtimeImageDigest', '') !~ '^sha256:[0-9a-f]{64}$'
    OR COALESCE(request_document->>'sourceSha256', '') !~ '^[0-9a-f]{64}$'
    OR COALESCE(request_document->>'cancellationRef', '') !~ '^cxl_[0-9a-f]{32}$'
    OR COALESCE(request_document->>'action', '') NOT IN ('RUN', 'SUBMIT')
    OR COALESCE(request_document->>'language', '') NOT IN ('java', 'python')
    OR COALESCE(request_document->>'runtimeVersion', '') = ''
    OR COALESCE(request_document->>'sourceArtifactId', '') !~ '^[A-Za-z0-9_-]{1,128}$'
    OR COALESCE(request_document->>'testBundleId', '') !~ '^[A-Za-z0-9_-]{1,128}$'
    OR COALESCE(request_document->>'problemVersionId', '') !~ '^[A-Za-z0-9_-]{1,128}$' THEN
    RAISE EXCEPTION 'protocol v2 request identity or policy fields are invalid'
      USING ERRCODE = '23514';
  END IF;

  limits_document := request_document->'limits';
  IF jsonb_typeof(limits_document) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'protocol v2 resource limits must be a JSON object'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO limits_key_count
  FROM jsonb_object_keys(limits_document);

  IF limits_key_count <> 7
    OR NOT (limits_document ?& ARRAY[
      'cpuQuotaMillis', 'memoryBytes', 'wallTimeMillis', 'processLimit',
      'outputBytes', 'scratchBytes', 'scratchInodes'
    ])
    OR COALESCE((limits_document->>'cpuQuotaMillis')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'memoryBytes')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'wallTimeMillis')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'processLimit')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'outputBytes')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'scratchBytes')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'scratchBytes')::bigint, 0) > 536870912
    OR COALESCE((limits_document->>'scratchInodes')::bigint, 0) <= 0
    OR COALESCE((limits_document->>'scratchInodes')::bigint, 0) > 8192 THEN
    RAISE EXCEPTION 'protocol v2 resource limits are invalid'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_protocol_request_consistency
  ON execution_protocol_requests;
CREATE TRIGGER trg_execution_protocol_request_consistency
BEFORE INSERT ON execution_protocol_requests
FOR EACH ROW EXECUTE FUNCTION verify_execution_protocol_request();

CREATE OR REPLACE FUNCTION prevent_execution_protocol_request_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  RAISE EXCEPTION 'persisted protocol v2 requests are immutable'
    USING ERRCODE = '55000';
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_protocol_requests_immutable
  ON execution_protocol_requests;
CREATE TRIGGER trg_execution_protocol_requests_immutable
BEFORE UPDATE OR DELETE ON execution_protocol_requests
FOR EACH ROW EXECUTE FUNCTION prevent_execution_protocol_request_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0014_execution_protocol_v2_requests',
  'Proposal: immutable byte-exact v2 execution requests bound to intake policy'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
