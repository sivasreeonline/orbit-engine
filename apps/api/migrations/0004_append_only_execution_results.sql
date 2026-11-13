BEGIN;

-- Append-only execution evidence. This migration extends the proposed 0003
-- intake schema; it is still a draft and is not deployed to any environment.

CREATE TABLE IF NOT EXISTS execution_evidence_events (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  execution_id uuid NOT NULL
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  event_type varchar(32) NOT NULL CHECK (event_type IN (
    'ATTEMPT_ACCEPTED',
    'JOB_QUEUED',
    'JOB_CLAIMED',
    'RUNNER_STARTED',
    'COMPILATION_STARTED',
    'COMPILATION_FINISHED',
    'TEST_STARTED',
    'TEST_FINISHED',
    'EXECUTION_FINISHED',
    'INFRASTRUCTURE_FAILED',
    'CANCELLED',
    'RETRY_SCHEDULED'
  )),
  actor_kind varchar(16) NOT NULL CHECK (actor_kind IN (
    'STUDENT', 'API', 'QUEUE', 'RUNNER', 'JUDGE', 'SYSTEM'
  )),
  phase_status varchar(24) NULL CHECK (
    phase_status IS NULL OR phase_status IN (
      'STARTED', 'SUCCEEDED', 'FAILED', 'SKIPPED', 'CANCELLED'
    )
  ),
  safe_code varchar(64) NULL CHECK (
    safe_code IS NULL OR safe_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  duration_ms bigint NULL CHECK (duration_ms IS NULL OR duration_ms >= 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_execution_evidence_events_timeline
  ON execution_evidence_events (execution_id, sequence_id);

CREATE INDEX IF NOT EXISTS idx_execution_evidence_events_owner
  ON execution_evidence_events (tenant_id, actor_user_id, created_at DESC);

CREATE OR REPLACE FUNCTION verify_execution_evidence_event_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_attempt_id uuid;
  expected_tenant_id uuid;
  expected_actor_user_id uuid;
BEGIN
  SELECT ej.attempt_id, ea.tenant_id, ea.actor_user_id
  INTO expected_attempt_id, expected_tenant_id, expected_actor_user_id
  FROM execution_jobs AS ej
  INNER JOIN execution_attempts AS ea ON ea.id = ej.attempt_id
  WHERE ej.id = NEW.execution_id;

  IF NOT FOUND
    OR expected_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR expected_tenant_id IS DISTINCT FROM NEW.tenant_id
    OR expected_actor_user_id IS DISTINCT FROM NEW.actor_user_id THEN
    RAISE EXCEPTION 'execution evidence event identity does not match its attempt'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_evidence_event_identity ON execution_evidence_events;
CREATE TRIGGER trg_execution_evidence_event_identity
BEFORE INSERT ON execution_evidence_events
FOR EACH ROW EXECUTE FUNCTION verify_execution_evidence_event_identity();

CREATE TABLE IF NOT EXISTS execution_result_records (
  execution_id uuid PRIMARY KEY
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL UNIQUE
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  infrastructure_status varchar(12) NOT NULL
    CHECK (infrastructure_status IN ('SUCCEEDED', 'FAILED')),
  infrastructure_error_code varchar(64) NULL CHECK (
    infrastructure_error_code IS NULL
    OR infrastructure_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  compilation_status varchar(12) NOT NULL
    CHECK (compilation_status IN ('NOT_STARTED', 'SUCCEEDED', 'FAILED')),
  verdict varchar(32) NOT NULL CHECK (verdict IN (
    'NOT_EVALUATED',
    'ACCEPTED',
    'WRONG_ANSWER',
    'COMPILATION_ERROR',
    'RUNTIME_ERROR',
    'TIME_LIMIT_EXCEEDED',
    'MEMORY_LIMIT_EXCEEDED',
    'OUTPUT_LIMIT_EXCEEDED',
    'INTERNAL_ERROR'
  )),
  cleanup_status varchar(12) NOT NULL
    CHECK (cleanup_status IN ('SUCCEEDED', 'FAILED', 'UNKNOWN')),
  tests_total integer NOT NULL DEFAULT 0 CHECK (tests_total >= 0),
  tests_passed integer NOT NULL DEFAULT 0 CHECK (
    tests_passed >= 0 AND tests_passed <= tests_total
  ),
  elapsed_ms bigint NOT NULL CHECK (elapsed_ms >= 0),
  peak_memory_bytes bigint NULL CHECK (
    peak_memory_bytes IS NULL OR peak_memory_bytes >= 0
  ),
  runner_version varchar(64) NOT NULL
    CHECK (length(runner_version) BETWEEN 1 AND 64),
  runtime_image_digest char(64) NULL CHECK (
    runtime_image_digest IS NULL
    OR runtime_image_digest ~ '^[0-9a-f]{64}$'
  ),
  result_sha256 char(64) NOT NULL
    CHECK (result_sha256 ~ '^[0-9a-f]{64}$'),
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT execution_result_time_order_ck CHECK (started_at <= completed_at),
  CONSTRAINT execution_result_infrastructure_outcome_ck CHECK (
    (infrastructure_status = 'FAILED'
      AND infrastructure_error_code IS NOT NULL
      AND verdict = 'NOT_EVALUATED')
    OR
    (infrastructure_status = 'SUCCEEDED'
      AND infrastructure_error_code IS NULL
      AND verdict <> 'NOT_EVALUATED')
  ),
  CONSTRAINT execution_result_compilation_verdict_ck CHECK (
    (compilation_status = 'FAILED' AND verdict = 'COMPILATION_ERROR')
    OR
    (compilation_status <> 'FAILED' AND verdict <> 'COMPILATION_ERROR')
  ),
  CONSTRAINT execution_result_compile_failure_tests_ck CHECK (
    compilation_status <> 'FAILED' OR tests_total = 0
  ),
  CONSTRAINT execution_result_accepted_tests_ck CHECK (
    verdict <> 'ACCEPTED' OR (tests_total > 0 AND tests_passed = tests_total)
  )
);

CREATE INDEX IF NOT EXISTS idx_execution_result_records_owner
  ON execution_result_records (tenant_id, actor_user_id, completed_at DESC);

CREATE OR REPLACE FUNCTION verify_execution_result_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_attempt_id uuid;
  expected_tenant_id uuid;
  expected_actor_user_id uuid;
BEGIN
  SELECT ej.attempt_id, ea.tenant_id, ea.actor_user_id
  INTO expected_attempt_id, expected_tenant_id, expected_actor_user_id
  FROM execution_jobs AS ej
  INNER JOIN execution_attempts AS ea ON ea.id = ej.attempt_id
  WHERE ej.id = NEW.execution_id;

  IF NOT FOUND
    OR expected_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR expected_tenant_id IS DISTINCT FROM NEW.tenant_id
    OR expected_actor_user_id IS DISTINCT FROM NEW.actor_user_id THEN
    RAISE EXCEPTION 'execution result identity does not match its attempt'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_result_identity ON execution_result_records;
CREATE TRIGGER trg_execution_result_identity
BEFORE INSERT ON execution_result_records
FOR EACH ROW EXECUTE FUNCTION verify_execution_result_identity();

CREATE OR REPLACE FUNCTION prevent_execution_result_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  RAISE EXCEPTION 'execution result evidence is immutable'
    USING ERRCODE = '55000';
END;
$function$;

DROP TRIGGER IF EXISTS trg_execution_evidence_events_immutable ON execution_evidence_events;
CREATE TRIGGER trg_execution_evidence_events_immutable
BEFORE UPDATE OR DELETE ON execution_evidence_events
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

DROP TRIGGER IF EXISTS trg_execution_result_records_immutable ON execution_result_records;
CREATE TRIGGER trg_execution_result_records_immutable
BEFORE UPDATE OR DELETE ON execution_result_records
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0004_append_only_execution_results',
  'Append-only runner lifecycle events and immutable, lease-fenced terminal results'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
