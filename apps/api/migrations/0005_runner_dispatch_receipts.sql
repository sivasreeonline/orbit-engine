BEGIN;

-- Durable receipt evidence for the runner's acceptance of a dispatch.
-- This is not an execution result and does not advance the execution job state.
CREATE TABLE IF NOT EXISTS runner_dispatch_receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dispatch_id uuid NOT NULL UNIQUE
    REFERENCES runner_dispatch_outbox(id) ON DELETE RESTRICT,
  runner_id varchar(128) NOT NULL
    CHECK (runner_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  receipt_id varchar(128) NOT NULL
    CHECK (receipt_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  receipt_hash char(64) NOT NULL
    CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
  accepted_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT runner_dispatch_receipt_runner_key UNIQUE (runner_id, receipt_id)
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_receipts_runner
  ON runner_dispatch_receipts (runner_id, created_at DESC);

CREATE OR REPLACE FUNCTION verify_runner_dispatch_receipt_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  dispatch_state varchar(16);
  dispatch_runner varchar(128);
  dispatch_expiry timestamptz;
BEGIN
  SELECT delivery_state, lease_owner, lease_expires_at
  INTO dispatch_state, dispatch_runner, dispatch_expiry
  FROM runner_dispatch_outbox
  WHERE id = NEW.dispatch_id
  FOR UPDATE;

  IF NOT FOUND
    OR dispatch_state <> 'PENDING'
    OR dispatch_runner IS DISTINCT FROM NEW.runner_id
    OR dispatch_expiry IS NULL
    OR dispatch_expiry <= now() THEN
    RAISE EXCEPTION 'runner dispatch receipt does not match active lease'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_receipt_lease ON runner_dispatch_receipts;
CREATE TRIGGER trg_runner_dispatch_receipt_lease
BEFORE INSERT ON runner_dispatch_receipts
FOR EACH ROW EXECUTE FUNCTION verify_runner_dispatch_receipt_lease();

CREATE OR REPLACE FUNCTION reject_runner_dispatch_receipt_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  RAISE EXCEPTION 'runner dispatch receipt is immutable'
    USING ERRCODE = '55000';
END;
$function$;

DROP TRIGGER IF EXISTS trg_runner_dispatch_receipt_immutable ON runner_dispatch_receipts;
CREATE TRIGGER trg_runner_dispatch_receipt_immutable
BEFORE UPDATE OR DELETE ON runner_dispatch_receipts
FOR EACH ROW EXECUTE FUNCTION reject_runner_dispatch_receipt_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0005_runner_dispatch_receipts',
  'Proposed immutable runner dispatch acceptance receipts'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
