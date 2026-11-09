-- Acceptance tests for immutable runner dispatch acceptance receipts.
-- Run after migrations 0001 through 0005 against a disposable database.
DO $block$
DECLARE
  execution_id uuid;
  attempt_id uuid;
  dispatch_id uuid;
  lease_token uuid := gen_random_uuid();
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
    execution_id, attempt_id, 'v1', 'runner-receipt-sql-test'
  ) RETURNING id INTO dispatch_id;

  UPDATE runner_dispatch_outbox
  SET lease_owner = 'sql-receipt-runner',
      lease_token = lease_token,
      lease_expires_at = now() + interval '1 minute'
  WHERE id = dispatch_id;

  INSERT INTO runner_dispatch_receipts (
    dispatch_id, runner_id, receipt_id, receipt_hash, accepted_at
  ) VALUES (
    dispatch_id, 'sql-receipt-runner', 'receipt-sql-001',
    repeat('a', 64), now()
  );

  UPDATE runner_dispatch_outbox
  SET delivery_state = 'DELIVERED', delivered_at = now(),
      lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
  WHERE id = dispatch_id;

  IF NOT EXISTS (
    SELECT 1 FROM runner_dispatch_receipts
    WHERE dispatch_id = dispatch_id
      AND runner_id = 'sql-receipt-runner'
      AND receipt_id = 'receipt-sql-001'
  ) THEN
    RAISE EXCEPTION 'Durable runner receipt was not persisted';
  END IF;

  blocked := false;
  BEGIN
    UPDATE runner_dispatch_receipts
    SET receipt_hash = repeat('b', 64)
    WHERE dispatch_id = dispatch_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner dispatch receipt mutation was not rejected';
  END IF;

  blocked := false;
  BEGIN
    DELETE FROM runner_dispatch_receipts WHERE dispatch_id = dispatch_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner dispatch receipt deletion was not rejected';
  END IF;
END
$block$;
