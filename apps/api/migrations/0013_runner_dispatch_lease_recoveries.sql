BEGIN;

-- An execution may be started more than once across lease generations after
-- a RUNNING lease expires. The immutable composite key still permits only one
-- start receipt for each dispatch + fencing-token generation.
ALTER TABLE runner_dispatch_starts
  DROP CONSTRAINT IF EXISTS runner_dispatch_starts_execution_id_key;

CREATE TABLE IF NOT EXISTS runner_dispatch_lease_recoveries (
  dispatch_id uuid NOT NULL
    REFERENCES runner_dispatch_outbox(id) ON DELETE RESTRICT,
  previous_lease_token uuid NOT NULL,
  previous_runner_id uuid NOT NULL
    REFERENCES runner_machines(id) ON DELETE RESTRICT,
  previous_key_id varchar(128) NOT NULL
    REFERENCES runner_machine_keys(key_id) ON DELETE RESTRICT,
  previous_start_event_id uuid NOT NULL
    REFERENCES execution_evidence_events(event_id) ON DELETE RESTRICT,
  new_lease_token uuid NOT NULL,
  new_runner_id uuid NOT NULL
    REFERENCES runner_machines(id) ON DELETE RESTRICT,
  execution_id uuid NOT NULL
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  recovery_attempt smallint NOT NULL CHECK (recovery_attempt BETWEEN 1 AND 3),
  event_id uuid NOT NULL UNIQUE
    REFERENCES execution_evidence_events(event_id) ON DELETE RESTRICT,
  recovered_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dispatch_id, previous_lease_token),
  UNIQUE (dispatch_id, new_lease_token),
  CONSTRAINT runner_dispatch_recovery_previous_start_fk
    FOREIGN KEY (dispatch_id, previous_lease_token)
    REFERENCES runner_dispatch_starts(dispatch_id, lease_token) ON DELETE RESTRICT,
  CONSTRAINT runner_dispatch_recovery_new_token_ck
    CHECK (new_lease_token <> previous_lease_token)
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_recoveries_execution
  ON runner_dispatch_lease_recoveries (execution_id, recovery_attempt);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_recoveries_runner
  ON runner_dispatch_lease_recoveries (new_runner_id, recovered_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_recovery_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  dispatch_execution_id uuid;
  dispatch_attempt_id uuid;
  dispatch_owner varchar(128);
  dispatch_token uuid;
  dispatch_expires_at timestamptz;
  job_state varchar(24);
  job_owner varchar(128);
  job_token uuid;
  job_expires_at timestamptz;
  job_retry_count integer;
  previous_runner_id uuid;
  previous_key_id varchar(128);
  previous_start_event_id uuid;
  event_execution_id uuid;
  event_attempt_id uuid;
  event_type varchar(32);
  event_actor_kind varchar(16);
  event_phase_status varchar(24);
  event_safe_code varchar(64);
BEGIN
  SELECT execution_id, attempt_id, lease_owner, lease_token, lease_expires_at
  INTO dispatch_execution_id, dispatch_attempt_id, dispatch_owner, dispatch_token, dispatch_expires_at
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id;

  SELECT state, lease_owner, lease_token, lease_expires_at, retry_count
  INTO job_state, job_owner, job_token, job_expires_at, job_retry_count
  FROM execution_jobs
  WHERE id = NEW.execution_id;

  SELECT start_receipt.runner_id, start_receipt.key_id, start_receipt.event_id
  INTO previous_runner_id, previous_key_id, previous_start_event_id
  FROM runner_dispatch_starts AS start_receipt
  WHERE start_receipt.dispatch_id = NEW.dispatch_id
    AND start_receipt.lease_token = NEW.previous_lease_token;

  SELECT evidence.execution_id, evidence.attempt_id, evidence.event_type,
    evidence.actor_kind, evidence.phase_status, evidence.safe_code
  INTO event_execution_id, event_attempt_id, event_type,
    event_actor_kind, event_phase_status, event_safe_code
  FROM execution_evidence_events AS evidence
  WHERE evidence.event_id = NEW.event_id;

  IF dispatch_execution_id IS DISTINCT FROM NEW.execution_id
    OR dispatch_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR dispatch_owner IS DISTINCT FROM NEW.new_runner_id::text
    OR dispatch_token IS DISTINCT FROM NEW.new_lease_token
    OR dispatch_expires_at IS NULL OR dispatch_expires_at <= clock_timestamp()
    OR job_state IS DISTINCT FROM 'CLAIMED'
    OR job_owner IS DISTINCT FROM NEW.new_runner_id::text
    OR job_token IS DISTINCT FROM NEW.new_lease_token
    OR job_expires_at IS NULL OR job_expires_at <= clock_timestamp()
    OR job_retry_count IS DISTINCT FROM NEW.recovery_attempt
    OR previous_runner_id IS DISTINCT FROM NEW.previous_runner_id
    OR previous_key_id IS DISTINCT FROM NEW.previous_key_id
    OR previous_start_event_id IS DISTINCT FROM NEW.previous_start_event_id
    OR event_execution_id IS DISTINCT FROM NEW.execution_id
    OR event_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR event_type IS DISTINCT FROM 'RETRY_SCHEDULED'
    OR event_actor_kind IS DISTINCT FROM 'JUDGE'
    OR event_phase_status IS DISTINCT FROM 'FAILED'
    OR event_safe_code IS DISTINCT FROM 'RUNNER_LEASE_EXPIRED' THEN
    RAISE EXCEPTION 'runner lease recovery does not match its previous and new lease generations'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_recovery_identity
  ON runner_dispatch_lease_recoveries;
CREATE TRIGGER trg_runner_dispatch_recovery_identity
BEFORE INSERT ON runner_dispatch_lease_recoveries
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_recovery_identity();

DROP TRIGGER IF EXISTS trg_runner_dispatch_recoveries_immutable
  ON runner_dispatch_lease_recoveries;
CREATE TRIGGER trg_runner_dispatch_recoveries_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_lease_recoveries
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0013_runner_dispatch_lease_recoveries',
  'Immutable RUNNING lease recovery receipts and repeated start generations'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
