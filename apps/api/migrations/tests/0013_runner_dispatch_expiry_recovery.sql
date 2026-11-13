BEGIN;

DO $block$
DECLARE
  recovery_table regclass;
  recovery_fk text;
  identity_trigger boolean;
  immutable_trigger boolean;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'runner_dispatch_starts'::regclass
      AND contype = 'u'
      AND pg_get_constraintdef(oid) = 'UNIQUE (execution_id)'
  ) THEN
    RAISE EXCEPTION 'a later lease generation must be allowed to start the same execution';
  END IF;

  recovery_table := to_regclass('runner_dispatch_recoveries');
  IF recovery_table IS NULL THEN
    RAISE EXCEPTION 'runner_dispatch_recoveries table is missing';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO recovery_fk
  FROM pg_constraint
  WHERE conrelid = recovery_table
    AND conname = 'runner_dispatch_recovery_started_fk';

  IF recovery_fk IS NULL
    OR position('FOREIGN KEY (dispatch_id, lease_token)' IN recovery_fk) = 0
    OR position('runner_dispatch_starts' IN recovery_fk) = 0 THEN
    RAISE EXCEPTION 'each recovery must reference the exact expired start generation';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = recovery_table
      AND contype = 'p'
      AND pg_get_constraintdef(oid) = 'PRIMARY KEY (dispatch_id, lease_token)'
  ) THEN
    RAISE EXCEPTION 'each lease generation may be recovered only once';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = recovery_table
      AND tgname = 'trg_runner_dispatch_recovery_identity'
      AND NOT tgisinternal
  ) INTO identity_trigger;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = recovery_table
      AND tgname = 'trg_runner_dispatch_recoveries_immutable'
      AND NOT tgisinternal
  ) INTO immutable_trigger;

  IF NOT identity_trigger OR NOT immutable_trigger THEN
    RAISE EXCEPTION 'runner recovery identity and immutability triggers are required';
  END IF;
END
$block$;

ROLLBACK;
