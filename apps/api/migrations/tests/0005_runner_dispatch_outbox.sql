-- Acceptance tests for the proposed durable runner dispatch outbox.
-- Run after migrations 0001 through 0004 against a disposable database.
DO $block$
DECLARE
  execution_id uuid;
  attempt_id uuid;
  dispatch_id uuid;
  blocked boolean := false;
BEGIN
  SELECT ej.id, ej.attempt_id INTO execution_id, attempt_id
  FROM execution_jobs AS ej
  INNER JOIN execution_outbox AS eo ON eo.execution_id = ej.id
  ORDER BY ej.created_at
  LIMIT 1;

  IF execution_id IS NULL THEN
    RAISE EXCEPTION 'Expected execution intake fixture from migration 0003 acceptance test';
  END IF;

  INSERT INTO runner_dispatch_outbox (
    execution_id, attempt_id, protocol_version, correlation_id
  ) VALUES (
    execution_id, attempt_id, 'v1', 'runner-handoff-sql-test'
  ) RETURNING id INTO dispatch_id;

  blocked := false;
  BEGIN
    INSERT INTO runner_dispatch_outbox (
      execution_id, attempt_id, protocol_version, correlation_id
    ) VALUES (
      execution_id,
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',
      'v1',
      'runner-handoff-wrong-attempt'
    );
  EXCEPTION WHEN check_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner dispatch accepted an attempt ID that does not match the execution job';
  END IF;

  blocked := false;
  BEGIN
    INSERT INTO runner_dispatch_outbox (
      execution_id, attempt_id, protocol_version, correlation_id
    ) VALUES (
      execution_id, attempt_id, 'v1', 'runner-handoff-duplicate'
    );
  EXCEPTION WHEN unique_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Duplicate runner dispatch intent was not rejected';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM runner_dispatch_outbox
    WHERE id = dispatch_id
      AND delivery_state = 'PENDING'
      AND delivered_at IS NULL
      AND lease_owner IS NULL
      AND lease_token IS NULL
      AND lease_expires_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Runner dispatch intent did not start in a recoverable pending state';
  END IF;
END
$block$;
