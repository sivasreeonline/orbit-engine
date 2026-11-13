BEGIN;

-- Operational lease-renewal receipts are distinct from student learning evidence.
-- Each heartbeat has a stable ID so a lost acknowledgement can be replayed.
CREATE TABLE IF NOT EXISTS runner_dispatch_lease_heartbeats (
  heartbeat_id uuid PRIMARY KEY,
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
  lease_expires_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT runner_dispatch_heartbeat_start_fk
    FOREIGN KEY (dispatch_id, lease_token)
    REFERENCES runner_dispatch_starts(dispatch_id, lease_token) ON DELETE RESTRICT,
  CONSTRAINT runner_dispatch_heartbeat_expiry_ck
    CHECK (lease_expires_at > recorded_at)
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_heartbeats_lease
  ON runner_dispatch_lease_heartbeats (dispatch_id, lease_token, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_heartbeats_runner
  ON runner_dispatch_lease_heartbeats (runner_id, recorded_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_heartbeat_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  dispatch_execution_id uuid;
  dispatch_attempt_id uuid;
  dispatch_owner varchar(128);
  dispatch_token uuid;
  dispatch_expires_at timestamptz;
  job_state varchar(16);
  job_owner varchar(128);
  job_token uuid;
  job_expires_at timestamptz;
  accepted_runner_id uuid;
  accepted_key_id varchar(128);
  started_runner_id uuid;
  started_key_id varchar(128);
BEGIN
  SELECT execution_id, attempt_id, lease_owner, lease_token, lease_expires_at
  INTO dispatch_execution_id, dispatch_attempt_id, dispatch_owner, dispatch_token, dispatch_expires_at
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id;

  SELECT state, lease_owner, lease_token, lease_expires_at
  INTO job_state, job_owner, job_token, job_expires_at
  FROM execution_jobs
  WHERE id = NEW.execution_id;

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

  IF dispatch_execution_id IS DISTINCT FROM NEW.execution_id
    OR dispatch_attempt_id IS DISTINCT FROM NEW.attempt_id
    OR dispatch_owner IS DISTINCT FROM NEW.runner_id::text
    OR dispatch_token IS DISTINCT FROM NEW.lease_token
    OR dispatch_expires_at IS NULL
    OR job_state IS DISTINCT FROM 'RUNNING'
    OR job_owner IS DISTINCT FROM NEW.runner_id::text
    OR job_token IS DISTINCT FROM NEW.lease_token
    OR job_expires_at IS NULL
    OR accepted_runner_id IS DISTINCT FROM NEW.runner_id
    OR accepted_key_id IS DISTINCT FROM NEW.key_id
    OR started_runner_id IS DISTINCT FROM NEW.runner_id
    OR started_key_id IS DISTINCT FROM NEW.key_id
    OR dispatch_expires_at <= now()
    OR job_expires_at <= now()
    OR NEW.lease_expires_at <= dispatch_expires_at
    OR NEW.lease_expires_at <= job_expires_at THEN
    RAISE EXCEPTION 'runner heartbeat does not match an active accepted and started lease'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_heartbeat_identity
  ON runner_dispatch_lease_heartbeats;
CREATE TRIGGER trg_runner_dispatch_heartbeat_identity
BEFORE INSERT ON runner_dispatch_lease_heartbeats
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_heartbeat_identity();

DROP TRIGGER IF EXISTS trg_runner_dispatch_heartbeats_immutable
  ON runner_dispatch_lease_heartbeats;
CREATE TRIGGER trg_runner_dispatch_heartbeats_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_lease_heartbeats
FOR EACH ROW EXECUTE FUNCTION prevent_execution_result_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0011_runner_dispatch_lease_heartbeats',
  'Idempotent immutable heartbeats for accepted and started runner leases'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
