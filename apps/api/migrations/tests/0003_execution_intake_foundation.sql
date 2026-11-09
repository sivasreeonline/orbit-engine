-- Acceptance tests for the proposed execution intake persistence schema.
-- Run after migrations 0001, 0002 and 0003 against a disposable database.

DO $block$
DECLARE
  snapshot_id uuid := 'dddddddd-dddd-4ddd-8ddd-ddddddddddd1';
  attempt_id uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1';
  second_snapshot_id uuid := 'dddddddd-dddd-4ddd-8ddd-ddddddddddd2';
  second_attempt_id uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2';
  execution_id uuid := 'ffffffff-ffff-4fff-8fff-fffffffffff1';
  tenant uuid := '30000000-0000-4000-8000-000000000001';
  actor uuid := '20000000-0000-4000-8000-000000000001';
  problem uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
  version uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1';
  source_hash char(64) := repeat('a', 64);
  second_source_hash char(64) := repeat('d', 64);
  blocked boolean;
BEGIN
  INSERT INTO source_snapshots (
    id, tenant_id, actor_user_id, sha256, byte_length,
    storage_kind, source_bytes
  ) VALUES (
    snapshot_id, tenant, actor, source_hash, 17,
    'DATABASE', convert_to('public class Main', 'UTF8')
  );

  INSERT INTO execution_attempts (
    id, tenant_id, actor_user_id, problem_id, problem_version_id,
    action, language, runtime_version, source_snapshot_id, source_sha256
  ) VALUES (
    attempt_id, tenant, actor, problem, version,
    'RUN', 'java', '25', snapshot_id, source_hash
  );

  INSERT INTO source_snapshots (
    id, tenant_id, actor_user_id, sha256, byte_length,
    storage_kind, source_bytes
  ) VALUES (
    second_snapshot_id, tenant, actor, second_source_hash, 1,
    'DATABASE', convert_to('x', 'UTF8')
  );

  INSERT INTO execution_attempts (
    id, tenant_id, actor_user_id, problem_id, problem_version_id,
    action, language, runtime_version, source_snapshot_id, source_sha256
  ) VALUES (
    second_attempt_id, tenant, actor, problem, version,
    'SUBMIT', 'python', '3.14', second_snapshot_id, second_source_hash
  );

  INSERT INTO execution_jobs (id, attempt_id)
  VALUES (execution_id, attempt_id);

  INSERT INTO execution_idempotency (
    tenant_id, actor_user_id, endpoint, idempotency_key,
    request_sha256, attempt_id
  ) VALUES (
    tenant, actor, 'RUN', 'test-idempotency-key-0001',
    repeat('b', 64), attempt_id
  );

  INSERT INTO execution_outbox (
    execution_id, event_type, protocol_version, correlation_id, payload
  ) VALUES (
    execution_id, 'EXECUTION_REQUESTED', 'v1', 'ci-execution-test',
    jsonb_build_object(
      'executionId', execution_id::text,
      'attemptId', attempt_id::text,
      'protocolVersion', 'v1'
    )
  );

  blocked := false;
  BEGIN
    UPDATE source_snapshots SET object_key = 'changed'
    WHERE id = snapshot_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Source snapshot mutation was not rejected';
  END IF;

  blocked := false;
  BEGIN
    DELETE FROM execution_attempts WHERE id = attempt_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Execution attempt deletion was not rejected';
  END IF;

  blocked := false;
  BEGIN
    INSERT INTO execution_idempotency (
      tenant_id, actor_user_id, endpoint, idempotency_key,
      request_sha256, attempt_id
    ) VALUES (
      tenant, actor, 'RUN', 'test-idempotency-key-0001',
      repeat('c', 64), attempt_id
    );
  EXCEPTION WHEN unique_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Duplicate scoped idempotency key was not rejected';
  END IF;

  blocked := false;
  BEGIN
    INSERT INTO execution_outbox (
      execution_id, event_type, protocol_version, correlation_id, payload
    ) VALUES (
      execution_id, 'EXECUTION_REQUESTED', 'v1', 'ci-execution-test',
      jsonb_build_object(
        'executionId', execution_id::text,
        'attemptId', attempt_id::text,
        'protocolVersion', 'v1',
        'sourceCode', 'must-not-be-queued'
      )
    );
  EXCEPTION WHEN unique_violation OR check_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Outbox accepted a payload containing source code or duplicate execution';
  END IF;

  blocked := false;
  BEGIN
    INSERT INTO execution_jobs (attempt_id, state)
    VALUES (
      attempt_id,
      'COMPLETED'
    );
  EXCEPTION WHEN unique_violation OR check_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Terminal job without completion timestamp was accepted';
  END IF;
END
$block$;
