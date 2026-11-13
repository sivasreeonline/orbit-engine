BEGIN;

-- A runner may start a dispatch only after the exact same lease generation
-- has a durable acceptance receipt. One execution can be started once.
CREATE TABLE IF NOT EXISTS runner_dispatch_starts (
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
  started_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dispatch_id, lease_token),
  UNIQUE (execution_id),
  CONSTRAINT runner_dispatch_start_acceptance_fk
    FOREIGN KEY (dispatch_id, lease_token)
    REFERENCES runner_dispatch_acceptances(dispatch_id, lease_token) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_starts_runner
  ON runner_dispatch_starts (runner_id, started_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_start_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_execution_id uuid;
  expected_attempt_id uuid;
  accepted_runner_id uuid;
  accepted_key_id varchar(128);
  event_execution_id uuid;
  event_attempt_id uuid;
  event_type varchar(32);
  event_actor_kind varchar(16);
  event_phase_status varchar(16);
BEGIN
  SELECT execution_id, attempt_id
  INTO expected_execution_id, expected_attempt_id
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id;

  SELECT runner_id, key_id
  INTO accepted_runner_id, accepted_key_id
  FROM runner_dispatch_acceptances
  WHERE dispatch_id = NEW.dispatch_id
    AND lease_token = NEW.lease_token;

  SELECT evidence.execution_id, evidence.attempt_id, evidence.event_type,
    evidence.actor_kind, evidence.phase_status
  INTO event_execution_id, event_attempt_id, event_type, event_actor_kind, event_phase_status
  FROM execution_evidence_events AS evidence
  WHERE evidence.event_id = NEW.event_id;

  IF expected_execution_id IS DISTINCT FROM NEW.execution_id
    OR expected_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR accepted_runner_id IS DISTINCT FROM NEW.runner_id
    OR accepted_key_id IS DISTINCT FROM NEW.key_id
    OR event_execution_id IS DISTINCT FROM NEW.execution_id
    OR event_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR event_type IS DISTINCT FROM 'RUNNER_STARTED'
    OR event_actor_kind IS DISTINCT FROM 'RUNNER'
    OR event_phase_status IS DISTINCT FROM 'STARTED' THEN
    RAISE EXCEPTION 'runner start identity does not match its dispatch, acceptance or evidence event'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_start_identity ON runner_dispatch_starts;
CREATE TRIGGER trg_runner_dispatch_start_identity
BEFORE INSERT ON runner_dispatch_starts
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_start_identity();

DROP TRIGGER IF EXISTS trg_runner_dispatch_starts_immutable ON runner_dispatch_starts;
CREATE TRIGGER trg_runner_dispatch_starts_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_starts
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0010_runner_dispatch_starts',
  'Lease-fenced runner start receipts and RUNNER_STARTED lifecycle evidence'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
