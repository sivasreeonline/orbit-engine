BEGIN;

DO $block$
DECLARE
  heartbeat_table regclass;
  start_fk text;
  identity_trigger boolean;
  immutable_trigger boolean;
BEGIN
  heartbeat_table := to_regclass('runner_dispatch_lease_heartbeats');
  IF heartbeat_table IS NULL THEN
    RAISE EXCEPTION 'runner_dispatch_lease_heartbeats table is missing';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO start_fk
  FROM pg_constraint
  WHERE conrelid = heartbeat_table
    AND conname = 'runner_dispatch_heartbeat_start_fk';

  IF start_fk IS NULL
    OR position('FOREIGN KEY (dispatch_id, lease_token)' IN start_fk) = 0
    OR position('runner_dispatch_starts' IN start_fk) = 0 THEN
    RAISE EXCEPTION 'runner heartbeat must reference the exact started lease generation';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = heartbeat_table
      AND tgname = 'trg_runner_dispatch_heartbeat_identity'
      AND NOT tgisinternal
  ) INTO identity_trigger;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = heartbeat_table
      AND tgname = 'trg_runner_dispatch_heartbeats_immutable'
      AND NOT tgisinternal
  ) INTO immutable_trigger;

  IF NOT identity_trigger OR NOT immutable_trigger THEN
    RAISE EXCEPTION 'runner heartbeat identity and immutability triggers are required';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = heartbeat_table
      AND contype = 'p'
      AND pg_get_constraintdef(oid) = 'PRIMARY KEY (heartbeat_id)'
  ) THEN
    RAISE EXCEPTION 'runner heartbeat IDs must be unique idempotency keys';
  END IF;
END
$block$;

ROLLBACK;
