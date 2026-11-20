BEGIN;

-- A terminal result is attributable to one authenticated runner and one
-- accepted/started lease generation. This receipt survives lease cleanup so a
-- lost HTTP acknowledgement can be retried without weakening fencing.
CREATE TABLE IF NOT EXISTS runner_dispatch_completions (
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
  event_id uuid NOT NULL UNIQUE
    REFERENCES execution_evidence_events(event_id) ON DELETE RESTRICT,
  result_sha256 char(64) NOT NULL
    CHECK (result_sha256 ~ '^[0-9a-f]{64}$'),
  terminal_state varchar(24) NOT NULL
    CHECK (terminal_state IN ('COMPLETED', 'FAILED_INFRASTRUCTURE')),
  completed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dispatch_id, lease_token),
  UNIQUE (execution_id),
  CONSTRAINT runner_dispatch_completion_start_fk
    FOREIGN KEY (dispatch_id, lease_token)
    REFERENCES runner_dispatch_starts(dispatch_id, lease_token) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_completions_runner
  ON runner_dispatch_completions (runner_id, completed_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_completion_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  dispatch_execution_id uuid;
  dispatch_attempt_id uuid;
  accepted_runner_id uuid;
  accepted_key_id varchar(128);
  started_runner_id uuid;
  started_key_id varchar(128);
  job_state varchar(24);
  job_attempt_id uuid;
  result_attempt_id uuid;
  result_sha256 char(64);
  result_state varchar(24);
  event_execution_id uuid;
  event_attempt_id uuid;
  event_type varchar(32);
  event_actor_kind varchar(16);
BEGIN
  SELECT execution_id, attempt_id
  INTO dispatch_execution_id, dispatch_attempt_id
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id;

  SELECT runner_id, key_id
  INTO accepted_runner_id, accepted_key_id
  FROM runner_dispatch_acceptances
  WHERE dispatch_id = NEW.dispatch_id
    AND lease_token = NEW.lease_token;

  SELECT runner_id, key_id
  INTO started_runner_id, started_key_id
  FROM runner_dispatch_starts
  WHERE dispatch_id = NEW.dispatch_id
    AND lease_token = NEW.lease_token;

  SELECT state, attempt_id
  INTO job_state, job_attempt_id
  FROM execution_jobs
  WHERE id = NEW.execution_id;

  SELECT result_record.attempt_id, result_record.result_sha256, result_record.infrastructure_status
  INTO result_attempt_id, result_sha256, result_state
  FROM execution_result_records AS result_record
  WHERE result_record.execution_id = NEW.execution_id;

  SELECT evidence.execution_id, evidence.attempt_id, evidence.event_type, evidence.actor_kind
  INTO event_execution_id, event_attempt_id, event_type, event_actor_kind
  FROM execution_evidence_events AS evidence
  WHERE evidence.event_id = NEW.event_id;

  IF dispatch_execution_id IS DISTINCT FROM NEW.execution_id
    OR dispatch_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR accepted_runner_id IS DISTINCT FROM NEW.runner_id
    OR accepted_key_id IS DISTINCT FROM NEW.key_id
    OR started_runner_id IS DISTINCT FROM NEW.runner_id
    OR started_key_id IS DISTINCT FROM NEW.key_id
    OR job_state IS DISTINCT FROM NEW.terminal_state
    OR job_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR result_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR result_sha256 IS DISTINCT FROM NEW.result_sha256
    OR (NEW.terminal_state = 'COMPLETED' AND result_state IS DISTINCT FROM 'SUCCEEDED')
    OR (NEW.terminal_state = 'FAILED_INFRASTRUCTURE' AND result_state IS DISTINCT FROM 'FAILED')
    OR event_execution_id IS DISTINCT FROM NEW.execution_id
    OR event_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR event_actor_kind IS DISTINCT FROM 'JUDGE'
    OR (NEW.terminal_state = 'COMPLETED' AND event_type IS DISTINCT FROM 'EXECUTION_FINISHED')
    OR (NEW.terminal_state = 'FAILED_INFRASTRUCTURE' AND event_type IS DISTINCT FROM 'INFRASTRUCTURE_FAILED') THEN
    RAISE EXCEPTION 'runner completion does not match its dispatch, lease, result or evidence event'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_completion_identity
  ON runner_dispatch_completions;
CREATE TRIGGER trg_runner_dispatch_completion_identity
BEFORE INSERT ON runner_dispatch_completions
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_completion_identity();

DROP TRIGGER IF EXISTS trg_runner_dispatch_completions_immutable
  ON runner_dispatch_completions;
CREATE TRIGGER trg_runner_dispatch_completions_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_completions
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0012_runner_dispatch_completions',
  'Immutable authenticated runner completion receipts bound to an accepted and started lease'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
