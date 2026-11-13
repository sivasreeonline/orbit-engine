BEGIN;

DO $block$
DECLARE
  machine_id uuid := gen_random_uuid();
  key_id_value varchar(128) := 'runner-identity-acceptance';
  nonce_value varchar(43) := 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8';
  inserted_nonce varchar(43);
  duplicate_nonce varchar(43);
  key_length integer;
BEGIN
  INSERT INTO runner_machines (id, machine_name)
  VALUES (machine_id, 'runner-identity-acceptance');

  INSERT INTO runner_machine_keys (key_id, runner_id, public_key)
  VALUES (key_id_value, machine_id, decode(repeat('11', 32), 'hex'));

  SELECT octet_length(public_key) INTO key_length
  FROM runner_machine_keys WHERE key_id = key_id_value;
  IF key_length <> 32 THEN
    RAISE EXCEPTION 'Runner public key must contain exactly 32 bytes';
  END IF;

  INSERT INTO runner_request_nonces (key_id, nonce, expires_at)
  VALUES (key_id_value, nonce_value, now() + interval '5 minutes')
  ON CONFLICT (key_id, nonce) DO NOTHING
  RETURNING nonce INTO inserted_nonce;

  INSERT INTO runner_request_nonces (key_id, nonce, expires_at)
  VALUES (key_id_value, nonce_value, now() + interval '5 minutes')
  ON CONFLICT (key_id, nonce) DO NOTHING
  RETURNING nonce INTO duplicate_nonce;

  IF inserted_nonce IS NULL OR duplicate_nonce IS NOT NULL THEN
    RAISE EXCEPTION 'Runner request nonce uniqueness was not enforced';
  END IF;

  UPDATE runner_machine_keys
  SET status = 'REVOKED', revoked_at = now()
  WHERE key_id = key_id_value;

  IF NOT EXISTS (
    SELECT 1 FROM runner_machine_keys
    WHERE key_id = key_id_value AND status = 'REVOKED' AND revoked_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Runner key revocation state was not persisted';
  END IF;

  DELETE FROM runner_request_nonces WHERE key_id = key_id_value;
  DELETE FROM runner_machine_keys WHERE key_id = key_id_value;
  DELETE FROM runner_machines WHERE id = machine_id;
END
$block$;

ROLLBACK;
