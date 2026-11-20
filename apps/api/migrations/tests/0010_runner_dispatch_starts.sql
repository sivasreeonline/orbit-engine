BEGIN;

DO $block$
DECLARE
  start_table regclass;
  identity_trigger boolean;
  immutable_trigger boolean;
  start_fk text;
  event_constraint text;
BEGIN
  start_table := to_regclass('runner_dispatch_starts');
  IF start_table IS NULL THEN
    RAISE EXCEPTION 'runner_dispatch_starts table is missing';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO start_fk
  FROM pg_constraint
  WHERE conrelid = start_table
    AND conname = 'runner_dispatch_start_acceptance_fk';

  IF start_fk IS NULL
    OR position('FOREIGN KEY (dispatch_id, lease_token)' IN start_fk) = 0
    OR position('runner_dispatch_acceptances' IN start_fk) = 0 THEN
    RAISE EXCEPTION 'runner start must reference the exact accepted lease generation';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = start_table
      AND contype = 'u'
      AND pg_get_constraintdef(oid) = 'UNIQUE (execution_id)'
  ) THEN
    RAISE EXCEPTION 'an execution must have at most one durable start receipt';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = start_table
      AND tgname = 'trg_runner_dispatch_start_identity'
      AND NOT tgisinternal
  ) INTO identity_trigger;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = start_table
      AND tgname = 'trg_runner_dispatch_starts_immutable'
      AND NOT tgisinternal
  ) INTO immutable_trigger;

  IF NOT identity_trigger OR NOT immutable_trigger THEN
    RAISE EXCEPTION 'runner start identity and immutability triggers are required';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO event_constraint
  FROM pg_constraint
  WHERE conrelid = 'execution_evidence_events'::regclass
    AND conname = 'execution_evidence_events_event_type_check';

  IF event_constraint IS NULL OR position('RUNNER_STARTED' IN event_constraint) = 0 THEN
    RAISE EXCEPTION 'RUNNER_STARTED lifecycle evidence is not allowed';
  END IF;
END
$block$;

ROLLBACK;
