BEGIN;

DO $block$
DECLARE
  completion_table regclass;
  start_fk text;
  identity_trigger boolean;
  immutable_trigger boolean;
BEGIN
  completion_table := to_regclass('runner_dispatch_completions');
  IF completion_table IS NULL THEN
    RAISE EXCEPTION 'runner_dispatch_completions table is missing';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO start_fk
  FROM pg_constraint
  WHERE conrelid = completion_table
    AND conname = 'runner_dispatch_completion_start_fk';

  IF start_fk IS NULL
    OR position('FOREIGN KEY (dispatch_id, lease_token)' IN start_fk) = 0
    OR position('runner_dispatch_starts' IN start_fk) = 0 THEN
    RAISE EXCEPTION 'completion receipt must reference the exact started lease';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = completion_table
      AND contype = 'p'
      AND pg_get_constraintdef(oid) = 'PRIMARY KEY (dispatch_id, lease_token)'
  ) THEN
    RAISE EXCEPTION 'completion receipt must be unique per dispatch lease generation';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = completion_table
      AND contype = 'u'
      AND pg_get_constraintdef(oid) = 'UNIQUE (execution_id)'
  ) THEN
    RAISE EXCEPTION 'execution may have only one terminal completion receipt';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = completion_table
      AND tgname = 'trg_runner_dispatch_completion_identity'
      AND NOT tgisinternal
  ) INTO identity_trigger;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = completion_table
      AND tgname = 'trg_runner_dispatch_completions_immutable'
      AND NOT tgisinternal
  ) INTO immutable_trigger;

  IF NOT identity_trigger OR NOT immutable_trigger THEN
    RAISE EXCEPTION 'completion identity and immutability triggers are required';
  END IF;
END
$block$;

ROLLBACK;
