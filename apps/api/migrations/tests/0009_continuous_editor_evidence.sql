BEGIN;

DO $block$
DECLARE
  tenant uuid := '11111111-1111-4111-8111-111111111111';
  actor uuid := '22222222-2222-4222-8222-222222222222';
  version_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1';
  problem_id uuid;
  session_id uuid;
  source_id uuid := '33333333-3333-4333-8333-333333333333';
  editor_snapshot_id uuid := '44444444-4444-4444-8444-444444444444';
  later_source_id uuid := '88888888-8888-4888-8888-888888888888';
  later_snapshot_id uuid := '99999999-9999-4999-8999-999999999999';
  blocked boolean := false;
BEGIN
  SELECT problem.id INTO problem_id
  FROM problems AS problem
  INNER JOIN problem_versions AS version
    ON version.problem_id = problem.id
  WHERE version.id = version_id
    AND problem.lifecycle_status = 'PUBLISHED'
    AND version.published_at IS NOT NULL;

  IF problem_id IS NULL THEN
    RAISE EXCEPTION 'Expected published Two Sum fixture for editor evidence test';
  END IF;

  INSERT INTO coding_evidence_sessions (
    tenant_id, actor_user_id, problem_id, problem_version_id,
    language, notice_version
  )
  VALUES (
    tenant, actor, problem_id, version_id, 'java', 'notice-v1'
  )
  RETURNING id INTO session_id;

  -- Empty editor documents are valid evidence and must hash to SHA-256(empty).
  INSERT INTO source_snapshots (
    id, tenant_id, actor_user_id, sha256, byte_length,
    storage_kind, source_bytes
  )
  VALUES (
    source_id, tenant, actor,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    0, 'DATABASE', convert_to('', 'UTF8')
  );

  INSERT INTO editor_code_snapshots (
    id, session_id, source_snapshot_id, sequence,
    snapshot_kind, language, captured_at
  )
  VALUES (
    editor_snapshot_id, session_id, source_id, 2,
    'SESSION_START', 'java', now()
  );

  INSERT INTO coding_evidence_events (
    event_id, session_id, sequence, event_type, client_occurred_at,
    language, payload_sha256
  )
  VALUES (
    '55555555-5555-4555-8555-555555555555', session_id, 1,
    'SESSION_STARTED', now(), 'java', repeat('a', 64)
  );

  INSERT INTO coding_evidence_events (
    event_id, session_id, sequence, event_type, client_occurred_at,
    language, snapshot_id, payload_sha256
  )
  VALUES (
    '66666666-6666-4666-8666-666666666666', session_id, 2,
    'CODE_SNAPSHOT_CREATED', now(), 'java', editor_snapshot_id, repeat('b', 64)
  );

  UPDATE coding_evidence_sessions SET last_sequence = 2 WHERE id = session_id;

  IF NOT EXISTS (
    SELECT 1 FROM source_snapshots
    WHERE id = source_id AND byte_length = 0 AND octet_length(source_bytes) = 0
  ) THEN
    RAISE EXCEPTION 'Empty editor snapshot was not stored correctly';
  END IF;

  blocked := false;
  BEGIN
    UPDATE coding_evidence_events
    SET metadata = '{"changed":true}'::jsonb
    WHERE event_id = '66666666-6666-4666-8666-666666666666';
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Coding evidence event update was not rejected';
  END IF;

  blocked := false;
  BEGIN
    DELETE FROM editor_code_snapshots WHERE id = editor_snapshot_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Editor code snapshot deletion was not rejected';
  END IF;

  INSERT INTO source_snapshots (
    id, tenant_id, actor_user_id, sha256, byte_length,
    storage_kind, source_bytes
  )
  VALUES (
    later_source_id, tenant, actor,
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    5, 'DATABASE', convert_to('hello', 'UTF8')
  );

  INSERT INTO editor_code_snapshots (
    id, session_id, source_snapshot_id, sequence,
    snapshot_kind, language, captured_at
  )
  VALUES (
    later_snapshot_id, session_id, later_source_id, 4,
    'PERIODIC', 'java', now()
  );

  blocked := false;
  BEGIN
    INSERT INTO coding_evidence_events (
      event_id, session_id, sequence, event_type, client_occurred_at,
      language, snapshot_id, payload_sha256
    )
    VALUES (
      '77777777-7777-4777-8777-777777777777', session_id, 3,
      'CHECKPOINT_RECORDED', now(), 'java', later_snapshot_id, repeat('c', 64)
    );
  EXCEPTION WHEN SQLSTATE '23514' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'An event referencing a later snapshot sequence was accepted';
  END IF;

  blocked := false;
  BEGIN
    UPDATE source_snapshots SET source_bytes = convert_to('other', 'UTF8')
    WHERE id = source_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'A referenced source snapshot was mutable';
  END IF;

  RAISE NOTICE 'Continuous editor evidence migration invariants passed';
END
$block$;

ROLLBACK;
