BEGIN;

DO $block$
DECLARE
  machine_id uuid := gen_random_uuid();
  supported_count integer;
BEGIN
  INSERT INTO runner_machines (id, machine_name)
  VALUES (machine_id, 'runner-capability-test-' || left(gen_random_uuid()::text, 8));

  IF EXISTS (
    SELECT 1 FROM runner_machine_protocol_capabilities
    WHERE runner_id = machine_id
  ) THEN
    RAISE EXCEPTION 'New runner unexpectedly received protocol capabilities';
  END IF;

  INSERT INTO runner_machine_protocol_capabilities (
    runner_id, protocol_version, qualification_reference
  ) VALUES (machine_id, 'v2', 'qualification-fixture-001');

  SELECT count(*) INTO supported_count
  FROM runner_machine_protocol_capabilities
  WHERE runner_id = machine_id
    AND protocol_version = 'v2'
    AND status = 'ACTIVE'
    AND revoked_at IS NULL;

  IF supported_count <> 1 THEN
    RAISE EXCEPTION 'Explicit v2 capability was not persisted';
  END IF;

  UPDATE runner_machine_protocol_capabilities
  SET status = 'REVOKED', revoked_at = now()
  WHERE runner_id = machine_id AND protocol_version = 'v2';

  IF EXISTS (
    SELECT 1 FROM runner_machine_protocol_capabilities
    WHERE runner_id = machine_id
      AND protocol_version = 'v2'
      AND status = 'ACTIVE'
      AND revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Revoked v2 capability remained active';
  END IF;

  DELETE FROM runner_machine_protocol_capabilities WHERE runner_id = machine_id;
  DELETE FROM runner_machines WHERE id = machine_id;
END
$block$;

ROLLBACK;
