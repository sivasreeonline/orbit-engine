BEGIN;

-- Proposal only: this migration is not part of the deployed migration sequence
-- until the request/result contracts, retention policy and identity mapping are approved.

CREATE TABLE IF NOT EXISTS source_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  sha256 char(64) NOT NULL
    CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  byte_length bigint NOT NULL CHECK (byte_length > 0),
  storage_kind varchar(8) NOT NULL
    CHECK (storage_kind IN ('DATABASE', 'R2')),
  source_bytes bytea NULL,
  object_key varchar(512) NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT source_snapshot_storage_location_ck CHECK (
    (storage_kind = 'DATABASE'
      AND source_bytes IS NOT NULL
      AND object_key IS NULL
      AND octet_length(source_bytes) = byte_length)
    OR
    (storage_kind = 'R2'
      AND source_bytes IS NULL
      AND object_key IS NOT NULL
      AND length(object_key) BETWEEN 1 AND 512)
  )
);

CREATE INDEX IF NOT EXISTS idx_source_snapshots_tenant_created
  ON source_snapshots (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS execution_attempts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  problem_id uuid NOT NULL REFERENCES problems(id) ON DELETE RESTRICT,
  problem_version_id uuid NOT NULL,
  action varchar(8) NOT NULL CHECK (action IN ('RUN', 'SUBMIT')),
  language varchar(16) NOT NULL CHECK (language IN ('java', 'python')),
  runtime_version varchar(32) NOT NULL
    CHECK (length(runtime_version) BETWEEN 1 AND 32),
  source_snapshot_id uuid NOT NULL
    REFERENCES source_snapshots(id) ON DELETE RESTRICT,
  source_sha256 char(64) NOT NULL
    CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT execution_attempt_problem_version_fk
    FOREIGN KEY (problem_version_id, problem_id)
    REFERENCES problem_versions(id, problem_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_execution_attempts_tenant_actor_created
  ON execution_attempts (tenant_id, actor_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_execution_attempts_problem_version
  ON execution_attempts (problem_version_id, created_at DESC);

CREATE OR REPLACE FUNCTION verify_execution_attempt_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  snapshot_tenant_id uuid;
  snapshot_actor_user_id uuid;
  snapshot_sha256 char(64);
BEGIN
  SELECT tenant_id, actor_user_id, sha256
    INTO snapshot_tenant_id, snapshot_actor_user_id, snapshot_sha256
  FROM source_snapshots
  WHERE id = NEW.source_snapshot_id;

  IF NOT FOUND
    OR snapshot_tenant_id IS DISTINCT FROM NEW.tenant_id
    OR snapshot_actor_user_id IS DISTINCT FROM NEW.actor_user_id
    OR snapshot_sha256 IS DISTINCT FROM NEW.source_sha256 THEN
    RAISE EXCEPTION 'execution attempt does not match its source snapshot'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_attempt_snapshot_consistency ON execution_attempts;
CREATE TRIGGER trg_execution_attempt_snapshot_consistency
BEFORE INSERT ON execution_attempts
FOR EACH ROW EXECUTE FUNCTION verify_execution_attempt_snapshot();

CREATE TABLE IF NOT EXISTS execution_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  attempt_id uuid NOT NULL UNIQUE
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  state varchar(24) NOT NULL DEFAULT 'QUEUED'
    CHECK (state IN (
      'QUEUED', 'CLAIMED', 'RUNNING', 'EVALUATING',
      'COMPLETED', 'FAILED_INFRASTRUCTURE', 'CANCELLED', 'EXPIRED'
    )),
  state_version bigint NOT NULL DEFAULT 1 CHECK (state_version > 0),
  retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  lease_owner varchar(128) NULL,
  lease_token uuid NULL,
  lease_expires_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz NULL,
  completed_at timestamptz NULL,
  CONSTRAINT execution_job_lease_fields_ck CHECK (
    (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CONSTRAINT execution_job_terminal_timestamp_ck CHECK (
    (state IN ('COMPLETED', 'FAILED_INFRASTRUCTURE', 'CANCELLED', 'EXPIRED')
      AND completed_at IS NOT NULL)
    OR
    (state NOT IN ('COMPLETED', 'FAILED_INFRASTRUCTURE', 'CANCELLED', 'EXPIRED')
      AND completed_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_execution_jobs_claimable
  ON execution_jobs (available_at, created_at)
  WHERE state = 'QUEUED';

CREATE INDEX IF NOT EXISTS idx_execution_jobs_expired_leases
  ON execution_jobs (lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS execution_idempotency (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  endpoint varchar(16) NOT NULL CHECK (endpoint IN ('RUN', 'SUBMIT')),
  idempotency_key varchar(128) NOT NULL
    CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_sha256 char(64) NOT NULL
    CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, actor_user_id, endpoint, idempotency_key)
);

CREATE TABLE IF NOT EXISTS execution_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id uuid NOT NULL REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  event_type varchar(32) NOT NULL CHECK (event_type = 'EXECUTION_REQUESTED'),
  protocol_version varchar(16) NOT NULL CHECK (protocol_version = 'v1'),
  correlation_id varchar(96) NOT NULL
    CHECK (correlation_id ~ '^[A-Za-z0-9._:-]{1,96}$'),
  payload jsonb NOT NULL,
  delivery_state varchar(16) NOT NULL DEFAULT 'PENDING'
    CHECK (delivery_state IN ('PENDING', 'PUBLISHED', 'DEAD_LETTER')),
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  lease_owner varchar(128) NULL,
  lease_token uuid NULL,
  lease_expires_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz NULL,
  CONSTRAINT execution_outbox_execution_unique UNIQUE (execution_id),
  CONSTRAINT execution_outbox_payload_shape_ck CHECK (
    jsonb_typeof(payload) = 'object'
    AND payload ? 'executionId'
    AND payload ? 'attemptId'
    AND payload ? 'protocolVersion'
    AND payload->>'executionId' = execution_id::text
    AND payload->>'protocolVersion' = protocol_version
    AND NOT (payload ?| ARRAY[
      'source', 'sourceCode', 'sourceBytes', 'hiddenTests',
      'expectedOutput', 'testBundle', 'databaseUrl', 'credentials'
    ])
  ),
  CONSTRAINT execution_outbox_lease_fields_ck CHECK (
    (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CONSTRAINT execution_outbox_published_timestamp_ck CHECK (
    (delivery_state = 'PUBLISHED' AND published_at IS NOT NULL)
    OR
    (delivery_state <> 'PUBLISHED' AND published_at IS NULL)
  )
);

CREATE OR REPLACE FUNCTION verify_execution_outbox_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_attempt_id uuid;
BEGIN
  SELECT attempt_id INTO expected_attempt_id
  FROM execution_jobs
  WHERE id = NEW.execution_id;

  IF NOT FOUND
    OR NEW.payload->>'attemptId' IS DISTINCT FROM expected_attempt_id::text THEN
    RAISE EXCEPTION 'outbox payload does not match its execution job'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_outbox_identity ON execution_outbox;
CREATE TRIGGER trg_execution_outbox_identity
BEFORE INSERT OR UPDATE ON execution_outbox
FOR EACH ROW EXECUTE FUNCTION verify_execution_outbox_identity();

CREATE INDEX IF NOT EXISTS idx_execution_outbox_pending
  ON execution_outbox (available_at, created_at)
  WHERE delivery_state = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_execution_outbox_expired_leases
  ON execution_outbox (lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;

CREATE OR REPLACE FUNCTION prevent_execution_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'execution evidence is immutable'
    USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_source_snapshots_immutable ON source_snapshots;
CREATE TRIGGER trg_source_snapshots_immutable
BEFORE UPDATE OR DELETE ON source_snapshots
FOR EACH ROW EXECUTE FUNCTION prevent_execution_evidence_mutation();

DROP TRIGGER IF EXISTS trg_execution_attempts_immutable ON execution_attempts;
CREATE TRIGGER trg_execution_attempts_immutable
BEFORE UPDATE OR DELETE ON execution_attempts
FOR EACH ROW EXECUTE FUNCTION prevent_execution_evidence_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0003_execution_intake_foundation',
  'Proposed immutable attempts, source snapshots, idempotency, jobs and outbox'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
