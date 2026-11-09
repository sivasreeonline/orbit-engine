-- Acceptance tests for immutable runner dispatch acceptance receipts.
-- Run after migrations 0001 through 0005 against a disposable database.
DO $block$
DECLARE
  v_dispatch_id uuid;
  v_lease_token uuid := gen_random_uuid();
  blocked boolean := false;
BEGIN
  SELECT id INTO v_dispatch_id
  FROM runner_dispatch_outbox
  WHERE delivery_state = 'PENDING'
  ORDER BY created_at
  LIMIT 1;

  IF v_dispatch_id IS NULL THEN
    RAISE EXCEPTION 'Expected pending runner dispatch fixture from migration 0004 acceptance test';
  END IF;

  UPDATE runner_dispatch_outbox
  SET lease_owner = 'sql-receipt-runner',
      lease_token = v_lease_token,
      lease_expires_at = now() + interval '1 minute'
  WHERE id = v_dispatch_id;

  INSERT INTO runner_dispatch_receipts (
    dispatch_id, runner_id, receipt_id, receipt_hash, accepted_at
  ) VALUES (
    v_dispatch_id, 'sql-receipt-runner', 'receipt-sql-001',
    repeat('a', 64), now()
  );

  UPDATE runner_dispatch_outbox
  SET delivery_state = 'DELIVERED', delivered_at = now(),
      lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
  WHERE id = v_dispatch_id;

  IF NOT EXISTS (
    SELECT 1 FROM runner_dispatch_receipts
    WHERE dispatch_id = v_dispatch_id
      AND runner_id = 'sql-receipt-runner'
      AND receipt_id = 'receipt-sql-001'
  ) THEN
    RAISE EXCEPTION 'Durable runner receipt was not persisted';
  END IF;

  blocked := false;
  BEGIN
    UPDATE runner_dispatch_receipts
    SET receipt_hash = repeat('b', 64)
    WHERE dispatch_id = v_dispatch_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner dispatch receipt mutation was not rejected';
  END IF;

  blocked := false;
  BEGIN
    DELETE FROM runner_dispatch_receipts WHERE dispatch_id = v_dispatch_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner dispatch receipt deletion was not rejected';
  END IF;
END
$block$;
