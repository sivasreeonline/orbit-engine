BEGIN;

DO $block$
DECLARE
  event_constraint text;
  acceptance_table regclass;
  immutable_trigger boolean;
BEGIN
  acceptance_table := to_regclass('runner_dispatch_acceptances');
  IF acceptance_table IS NULL THEN
    RAISE EXCEPTION 'runner_dispatch_acceptances table is missing';
  END IF;

  SELECT pg_get_constraintdef(oid)
  INTO event_constraint
  FROM pg_constraint
  WHERE conrelid = 'execution_evidence_events'::regclass
    AND conname = 'execution_evidence_events_event_type_check';

  IF event_constraint IS NULL OR position('RUNNER_ACCEPTED' IN event_constraint) = 0 THEN
    RAISE EXCEPTION 'RUNNER_ACCEPTED evidence event is not allowed';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = acceptance_table
      AND tgname = 'trg_runner_dispatch_acceptances_immutable'
      AND NOT tgisinternal
  ) INTO immutable_trigger;

  IF NOT immutable_trigger THEN
    RAISE EXCEPTION 'runner acceptance immutability trigger is missing';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = acceptance_table
      AND contype = 'p'
      AND pg_get_constraintdef(oid) LIKE '%dispatch_id, lease_token%'
  ) THEN
    RAISE EXCEPTION 'runner acceptance uniqueness must be scoped to dispatch and lease token';
  END IF;
END
$block$;

ROLLBACK;
