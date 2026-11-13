BEGIN;

-- A retry may start the same execution under a fresh lease generation. The
-- composite dispatch/lease primary key remains the idempotency boundary.
ALTER TABLE runner_dispatch_starts
  DROP CONSTRAINT IF EXISTS runner_dispatch_starts_execution_id_key;

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_starts_execution
  ON runner_dispatch_starts (execution_id, started_at DESC);

-- Each expired RUNNING lease receives one durable recovery decision. The same
-- execution may be requeued for another lease, so recovery identity is per
-- dispatch + lease token, not per execution.
CREATE TABLE IF NOT EXISTS runner_dispatch_recoveries (
  recovery_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  dispatch_id uuid NOT NULL,
  lease_token uuid NOT NULL,
  execution_id uuid NOT NULL
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  runner_id uuid NOT NULL
    REFERENCES runner_machines(id) ON DELETE RESTRICT,
  key_id varchar(128) NOT NULL
    REFERENCES runner_machine_keys(key_id) ON DELETE RESTRICT,
  recovery_worker_id varchar(128) NOT NULL
    CHECK (recovery_worker_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  event_id uuid NOT NULL UNIQUE
    REFERENCES execution_evidence_events(event_id) ON DELETE RESTRICT,
  recovery_action varchar(24) NOT NULL
    CHECK (recovery_action IN ('REQUEUED', 'FAILED_INFRASTRUCTURE')),
  retry_count integer NOT NULL CHECK (retry_count >= 0),
  prior_lease_expires_at timestamptz NOT NULL,
  available_at timestamptz NULL,
  recovered_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dispatch_id, lease_token),
  CONSTRAINT runner_dispatch_recovery_started_fk
    FOREIGN KEY (dispatch_id, lease_token)
    REFERENCES runner_dispatch_starts(dispatch_id, lease_token) ON DELETE RESTRICT,
  CONSTRAINT runner_dispatch_recovery_action_fields_ck CHECK (
    (recovery_action = 'REQUEUED' AND available_at IS NOT NULL)
    OR
    (recovery_action = 'FAILED_INFRASTRUCTURE' AND available_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_recoveries_execution
  ON runner_dispatch_recoveries (execution_id, recovered_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_recovery_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  dispatch_execution_id uuid;
  dispatch_attempt_id uuid;
  started_runner_id uuid;
  started_key_id varchar(128);
  job_state varchar(24);
  job_attempt_id uuid;
  job_retry_count integer;
  job_available_at timestamptz;
  job_lease_owner varchar(128);
  job_lease_token uuid;
  job_lease_expires_at timestamptz;
  dispatch_state varchar(16);
  dispatch_lease_owner varchar(128);
  dispatch_lease_token uuid;
  dispatch_lease_expires_at timestamptz;
  dispatch_available_at timestamptz;
  result_status varchar(12);
  result_error_code varchar(64);
  event_execution_id uuid;
  event_attempt_id uuid;
  event_type varchar(32);
  event_actor_kind varchar(16);
  event_phase_status varchar(24);
  event_safe_code varchar(64);
BEGIN
  SELECT execution_id, attempt_id, delivery_state, lease_owner, lease_token,
    lease_expires_at, available_at
  INTO dispatch_execution_id, dispatch_attempt_id, dispatch_state,
    dispatch_lease_owner, dispatch_lease_token, dispatch_lease_expires_at,
    dispatch_available_at
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id;

  SELECT runner_id, key_id
  INTO started_runner_id, started_key_id
  FROM runner_dispatch_starts
  WHERE dispatch_id = NEW.dispatch_id AND lease_token = NEW.lease_token;

  SELECT state, attempt_id, retry_count, available_at, lease_owner, lease_token, lease_expires_at
  INTO job_state, job_attempt_id, job_retry_count, job_available_at, job_lease_owner,
    job_lease_token, job_lease_expires_at
  FROM execution_jobs
  WHERE id = NEW.execution_id;

  SELECT execution_id, attempt_id, event_type, actor_kind, phase_status, safe_code
  INTO event_execution_id, event_attempt_id, event_type, event_actor_kind,
    event_phase_status, event_safe_code
  FROM execution_evidence_events
  WHERE event_id = NEW.event_id;

  IF dispatch_execution_id IS DISTINCT FROM NEW.execution_id
    OR dispatch_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR started_runner_id IS DISTINCT FROM NEW.runner_id
    OR started_key_id IS DISTINCT FROM NEW.key_id
    OR job_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR job_retry_count IS DISTINCT FROM NEW.retry_count
    OR job_lease_owner IS NOT NULL
    OR job_lease_token IS NOT NULL
    OR job_lease_expires_at IS NOT NULL
    OR dispatch_lease_owner IS NOT NULL
    OR dispatch_lease_token IS NOT NULL
    OR dispatch_lease_expires_at IS NOT NULL
    OR event_execution_id IS DISTINCT FROM NEW.execution_id
    OR event_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR event_actor_kind IS DISTINCT FROM 'SYSTEM' THEN
    RAISE EXCEPTION 'runner recovery does not match the fenced dispatch, start or event identity'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.recovery_action = 'REQUEUED' THEN
    IF job_state IS DISTINCT FROM 'QUEUED'
      OR dispatch_state IS DISTINCT FROM 'PENDING'
      OR dispatch_available_at IS DISTINCT FROM NEW.available_at
      OR job_available_at IS DISTINCT FROM NEW.available_at
      OR event_type IS DISTINCT FROM 'RETRY_SCHEDULED'
      OR event_phase_status IS DISTINCT FROM 'SUCCEEDED'
      OR event_safe_code IS DISTINCT FROM 'RUNNER_LEASE_EXPIRED' THEN
      RAISE EXCEPTION 'requeued runner recovery state or event is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    SELECT infrastructure_status, infrastructure_error_code
    INTO result_status, result_error_code
    FROM execution_result_records
    WHERE execution_id = NEW.execution_id
      AND attempt_id = NEW.attempt_id;

    IF job_state IS DISTINCT FROM 'FAILED_INFRASTRUCTURE'
      OR dispatch_state IS DISTINCT FROM 'DEAD_LETTER'
      OR event_type IS DISTINCT FROM 'INFRASTRUCTURE_FAILED'
      OR event_phase_status IS DISTINCT FROM 'FAILED'
      OR event_safe_code IS DISTINCT FROM 'RUNNER_LEASE_EXPIRED'
      OR result_status IS DISTINCT FROM 'FAILED'
      OR result_error_code IS DISTINCT FROM 'RUNNER_LEASE_EXPIRED' THEN
      RAISE EXCEPTION 'terminal runner recovery result or event is invalid'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_recovery_identity
  ON runner_dispatch_recoveries;
CREATE TRIGGER trg_runner_dispatch_recovery_identity
BEFORE INSERT ON runner_dispatch_recoveries
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_recovery_identity();

DROP TRIGGER IF EXISTS trg_runner_dispatch_recoveries_immutable
  ON runner_dispatch_recoveries;
CREATE TRIGGER trg_runner_dispatch_recoveries_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_recoveries
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0013_runner_dispatch_expiry_recovery',
  'Retryable lease-expiry recovery with immutable per-lease receipts'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
