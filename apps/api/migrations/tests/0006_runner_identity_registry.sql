-- Acceptance tests for the provider-neutral runner identity registry.
-- Run after migrations 0001 through 0006 on a disposable PostgreSQL database.
DO $block$
DECLARE
  v_pool_id uuid;
  v_identity_id uuid;
  v_event_id uuid;
  blocked boolean := false;
BEGIN
  INSERT INTO runner_pools (pool_key)
  VALUES ('ci-runner-pool')
  RETURNING id INTO v_pool_id;

  INSERT INTO runner_identities (
    runner_id, pool_id, identity_issuer, identity_subject, scopes
  ) VALUES (
    'ci-runner-001', v_pool_id, 'https://identity.example.test',
    'service-subject-001', ARRAY['dispatch:claim', 'dispatch:receipt']
  )
  RETURNING id INTO v_identity_id;

  IF NOT EXISTS (
    SELECT 1 FROM runner_identity_events
    WHERE runner_identity_id = v_identity_id
      AND event_type = 'REGISTERED'
      AND new_status = 'ACTIVE'
  ) THEN
    RAISE EXCEPTION 'Runner registration event was not recorded';
  END IF;

  blocked := false;
  BEGIN
    INSERT INTO runner_identities (
      runner_id, pool_id, identity_issuer, identity_subject, scopes
    ) VALUES (
      'ci-runner-duplicate', v_pool_id, 'https://identity.example.test',
      'service-subject-001', ARRAY['dispatch:claim']
    );
  EXCEPTION WHEN unique_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Duplicate issuer/subject identity binding was accepted';
  END IF;

  blocked := false;
  BEGIN
    INSERT INTO runner_identities (
      runner_id, pool_id, identity_issuer, identity_subject, scopes
    ) VALUES (
      'ci-runner-invalid-scope', v_pool_id, 'https://identity.example.test',
      'service-subject-invalid', ARRAY['dispatch:admin']
    );
  EXCEPTION WHEN check_violation THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Unknown runner scope was accepted';
  END IF;

  blocked := false;
  BEGIN
    UPDATE runner_identities
    SET identity_subject = 'attacker-subject'
    WHERE id = v_identity_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Registered machine identity binding was mutable';
  END IF;

  UPDATE runner_identities SET status = 'SUSPENDED'
  WHERE id = v_identity_id;
  UPDATE runner_identities SET scopes = ARRAY['dispatch:claim']
  WHERE id = v_identity_id;

  IF (SELECT count(*) FROM runner_identity_events
      WHERE runner_identity_id = v_identity_id
        AND event_type = 'STATUS_CHANGED') <> 1 THEN
    RAISE EXCEPTION 'Runner status lifecycle event was not recorded';
  END IF;
  IF (SELECT count(*) FROM runner_identity_events
      WHERE runner_identity_id = v_identity_id
        AND event_type = 'SCOPES_CHANGED') <> 1 THEN
    RAISE EXCEPTION 'Runner scope lifecycle event was not recorded';
  END IF;

  UPDATE runner_identities SET status = 'REVOKED'
  WHERE id = v_identity_id;
  IF NOT EXISTS (
    SELECT 1 FROM runner_identities
    WHERE id = v_identity_id
      AND status = 'REVOKED'
      AND revoked_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Runner revocation timestamp was not generated';
  END IF;

  blocked := false;
  BEGIN
    UPDATE runner_identities SET status = 'ACTIVE'
    WHERE id = v_identity_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Revoked runner identity was reactivated';
  END IF;

  blocked := false;
  BEGIN
    DELETE FROM runner_identities WHERE id = v_identity_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner identity hard deletion was accepted';
  END IF;

  SELECT id INTO v_event_id
  FROM runner_identity_events
  WHERE runner_identity_id = v_identity_id
  ORDER BY occurred_at
  LIMIT 1;

  blocked := false;
  BEGIN
    UPDATE runner_identity_events SET event_type = 'STATUS_CHANGED'
    WHERE id = v_event_id;
  EXCEPTION WHEN SQLSTATE '55000' THEN
    blocked := true;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'Runner lifecycle event mutation was accepted';
  END IF;

  UPDATE runner_pools SET status = 'DISABLED'
  WHERE id = v_pool_id;
  IF NOT EXISTS (
    SELECT 1 FROM runner_pools
    WHERE id = v_pool_id AND status = 'DISABLED'
  ) THEN
    RAISE EXCEPTION 'Runner pool disable operation failed';
  END IF;
END
$block$;
