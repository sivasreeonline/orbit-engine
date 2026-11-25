BEGIN;

DO $block$
DECLARE
  request_table regclass;
  identity_trigger boolean;
  immutable_trigger boolean;
  request_guard text;
  deadline_constraint text;
BEGIN
  request_table := to_regclass('execution_protocol_requests');
  IF request_table IS NULL THEN
    RAISE EXCEPTION 'execution_protocol_requests table is missing';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'execution_protocol_requests'
      AND column_name = 'request_bytes'
      AND data_type = 'bytea'
  ) OR NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'execution_protocol_requests'
      AND column_name = 'request_sha256'
  ) OR NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'execution_protocol_requests'
      AND column_name = 'intake_at'
  ) THEN
    RAISE EXCEPTION 'byte-exact request, digest and trusted intake timestamp must be persisted';
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'execution_protocol_requests'
      AND column_name IN ('source_code', 'test_cases', 'expected_output', 'hidden_tests')
  ) THEN
    RAISE EXCEPTION 'protocol request storage must contain references, not source or test payloads';
  END IF;

  SELECT pg_get_constraintdef(oid)
    INTO deadline_constraint
  FROM pg_constraint
  WHERE conrelid = request_table
    AND conname = 'execution_protocol_request_deadline_ck';

  IF deadline_constraint IS NULL
    OR (position('00:10:00' IN deadline_constraint) = 0
      AND position('10 minutes' IN deadline_constraint) = 0) THEN
    RAISE EXCEPTION 'protocol request deadline must be bounded by trusted intake plus ten minutes';
  END IF;

  SELECT pg_get_functiondef('verify_execution_protocol_request()'::regprocedure)
    INTO request_guard;

  IF request_guard IS NULL
    OR position('protocolVersion' IN request_guard) = 0
    OR position('EXACT_BYTES' IN request_guard) = 0
    OR position('runtimeImageDigest' IN request_guard) = 0
    OR position('cancellationRef' IN request_guard) = 0
    OR position('scratchBytes' IN request_guard) = 0
    OR position('scratchInodes' IN request_guard) = 0 THEN
    RAISE EXCEPTION 'v2 identity, runtime, cancellation and resource policy checks are required';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = request_table
      AND tgname = 'trg_execution_protocol_request_consistency'
      AND NOT tgisinternal
  ) INTO identity_trigger;

  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = request_table
      AND tgname = 'trg_execution_protocol_requests_immutable'
      AND NOT tgisinternal
  ) INTO immutable_trigger;

  IF NOT identity_trigger OR NOT immutable_trigger THEN
    RAISE EXCEPTION 'v2 request identity validation and append-only custody triggers are required';
  END IF;
END
$block$;

ROLLBACK;
