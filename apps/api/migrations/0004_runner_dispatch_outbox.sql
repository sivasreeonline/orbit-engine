BEGIN;

-- Proposal-stage durable handoff record. Applied only in disposable CI until
-- the execution contracts and operational policy are approved.
CREATE TABLE IF NOT EXISTS runner_dispatch_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id uuid NOT NULL UNIQUE
    REFERENCES execution_jobs(id) ON DELETE RESTRICT,
  attempt_id uuid NOT NULL
    REFERENCES execution_attempts(id) ON DELETE RESTRICT,
  protocol_version varchar(16) NOT NULL CHECK (protocol_version = 'v1'),
  correlation_id varchar(96) NOT NULL
    CHECK (correlation_id ~ '^[A-Za-z0-9._:-]{1,96}$'),
  delivery_state varchar(16) NOT NULL DEFAULT 'PENDING'
    CHECK (delivery_state IN ('PENDING', 'DELIVERED', 'DEAD_LETTER')),
  delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  lease_owner varchar(128) NULL,
  lease_token uuid NULL,
  lease_expires_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz NULL,
  CONSTRAINT runner_dispatch_attempt_matches_job_ck
    CHECK (attempt_id IS NOT NULL),
  CONSTRAINT runner_dispatch_lease_fields_ck CHECK (
    (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CONSTRAINT runner_dispatch_delivered_timestamp_ck CHECK (
    (delivery_state = 'DELIVERED' AND delivered_at IS NOT NULL)
    OR (delivery_state <> 'DELIVERED' AND delivered_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_pending
  ON runner_dispatch_outbox (available_at, created_at, id)
  WHERE delivery_state = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_expired_leases
  ON runner_dispatch_outbox (lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;

CREATE OR REPLACE FUNCTION verify_runner_dispatch_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  expected_attempt_id uuid;
BEGIN
  SELECT attempt_id INTO expected_attempt_id
  FROM execution_jobs
  WHERE id = NEW.execution_id;

  IF NOT FOUND OR NEW.attempt_id IS DISTINCT FROM expected_attempt_id THEN
    RAISE EXCEPTION 'runner dispatch attempt does not match execution job'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_identity ON runner_dispatch_outbox;
CREATE TRIGGER trg_runner_dispatch_identity
BEFORE INSERT OR UPDATE ON runner_dispatch_outbox
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_identity();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0004_runner_dispatch_outbox',
  'Proposed durable queue-to-runner handoff records'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
