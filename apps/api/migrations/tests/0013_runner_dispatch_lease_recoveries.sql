BEGIN;

DO $block$
DECLARE
  start_table regclass;
  recovery_table regclass;
  identity_trigger boolean;
  immutable_trigger boolean;
  previous_start_fk text;
  unique_execution boolean;
BEGIN
  start_table := to_regclass('runner_dispatch_starts');
  recovery_table := to_regclass('runner_dispatch_lease_recoveries');

  IF start_table IS NULL OR recovery_table IS NULL THEN
    RAISE EXCEPTION 'runner start or recovery table is missing';
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = start_table
      AND contype = 'u'
      AND pg_get_constraintdef(oid) = 'UNIQUE (execution_id)'
  ) INTO unique_execution;

  IF unique_execution THEN
    RAISE EXCEPTION 'an execution must permit multiple start receipts across lease generations';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = start_table
      AND contype = 'p'
      AND pg_get_constraintdef(oid) = 'PRIMARY KEY (dispatch_id, lease_token)'
  ) THEN
    RAISE EXCEPTION 'start receipts must remain unique per lease generation';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO previous_start_fk
  FROM pg_constraint
  WHERE conrelid = recovery_table
    AND conname = 'runner_dispatch_recovery_previous_start_fk';

  IF previous_start_fk IS NULL
    OR position('FOREIGN KEY (dispatch_id, previous_lease_token)' IN previous_start_fk) = 0
    OR position('runner_dispatch_starts' IN previous_start_fk) = 0 THEN
    RAISE EXCEPTION 'recovery receipt must reference the exact previous start generation';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = recovery_table
      AND contype = 'p'
      AND pg_get_constraintdef(oid) = 'PRIMARY KEY (dispatch_id, previous_lease_token)'
  ) THEN
    RAISE EXCEPTION 'a previous lease generation may be recovered only once';
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
    RAISE EXCEPTION 'recovery identity and immutability triggers are required';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = recovery_table
      AND conname = 'runner_dispatch_recovery_new_token_ck'
  ) THEN
    RAISE EXCEPTION 'new recovery token must differ from previous fencing token';
  END IF;
END
$block$;

ROLLBACK;
