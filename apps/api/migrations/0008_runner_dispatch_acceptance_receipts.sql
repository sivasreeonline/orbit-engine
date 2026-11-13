BEGIN;

-- Runner acceptance is a separate durable checkpoint from queue dispatch.
-- Each lease generation may have at most one acceptance receipt.
ALTER TABLE execution_evidence_events
  DROP CONSTRAINT IF EXISTS execution_evidence_events_event_type_check;

ALTER TABLE execution_evidence_events
  ADD CONSTRAINT execution_evidence_events_event_type_check CHECK (event_type IN (
    'ATTEMPT_ACCEPTED',
    'JOB_QUEUED',
    'JOB_CLAIMED',
    'RUNNER_ACCEPTED',
    'RUNNER_STARTED',
    'COMPILATION_STARTED',
    'COMPILATION_FINISHED',
    'TEST_STARTED',
    'TEST_FINISHED',
    'EXECUTION_FINISHED',
    'INFRASTRUCTURE_FAILED',
    'CANCELLED',
    'RETRY_SCHEDULED'
  ));

CREATE TABLE IF NOT EXISTS runner_dispatch_acceptances (
  dispatch_id uuid NOT NULL
    REFERENCES runner_dispatch_outbox(id) ON DELETE RESTRICT,
  lease_token uuid NOT NULL,
  acceptance_id uuid NOT NULL UNIQUE,
  event_id uuid NOT NULL UNIQUE
    REFERENCES execution_evidence_events(event_id) ON DELETE RESTRICT,
  execution_id uuid NOT NULL
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  runner_id uuid NOT NULL
    REFERENCES runner_machines(id) ON DELETE RESTRICT,
  key_id varchar(128) NOT NULL
    REFERENCES runner_machine_keys(key_id) ON DELETE RESTRICT,
  receipt_sha256 char(64) NOT NULL
    CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  accepted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dispatch_id, lease_token)
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_acceptances_runner
  ON runner_dispatch_acceptances (runner_id, accepted_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_acceptance_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_execution_id uuid;
  expected_attempt_id uuid;
  expected_key_runner_id uuid;
  event_execution_id uuid;
  event_attempt_id uuid;
  event_type varchar(32);
  event_actor_kind varchar(16);
BEGIN
  SELECT execution_id, attempt_id
  INTO expected_execution_id, expected_attempt_id
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id;

  SELECT runner_id INTO expected_key_runner_id
  FROM runner_machine_keys
  WHERE key_id = NEW.key_id;

  SELECT evidence.execution_id, evidence.attempt_id,
    evidence.event_type, evidence.actor_kind
  INTO event_execution_id, event_attempt_id, event_type, event_actor_kind
  FROM execution_evidence_events AS evidence
  WHERE evidence.event_id = NEW.event_id;

  IF expected_execution_id IS DISTINCT FROM NEW.execution_id
    OR expected_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR expected_key_runner_id IS DISTINCT FROM NEW.runner_id
    OR event_execution_id IS DISTINCT FROM NEW.execution_id
    OR event_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR event_type IS DISTINCT FROM 'RUNNER_ACCEPTED'
    OR event_actor_kind IS DISTINCT FROM 'RUNNER' THEN
    RAISE EXCEPTION 'runner acceptance identity does not match its dispatch, key or evidence event'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_acceptance_identity
  ON runner_dispatch_acceptances;
CREATE TRIGGER trg_runner_dispatch_acceptance_identity
BEFORE INSERT ON runner_dispatch_acceptances
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_acceptance_identity();

DROP TRIGGER IF EXISTS trg_runner_dispatch_acceptances_immutable
  ON runner_dispatch_acceptances;
CREATE TRIGGER trg_runner_dispatch_acceptances_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_acceptances
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0008_runner_dispatch_acceptance_receipts',
  'Append-only authenticated runner acceptance receipts and lifecycle evidence'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
