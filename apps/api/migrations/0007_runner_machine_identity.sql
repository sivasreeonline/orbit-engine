BEGIN;

CREATE TABLE IF NOT EXISTS runner_machines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  machine_name varchar(128) NOT NULL UNIQUE
    CHECK (machine_name ~ '^[A-Za-z0-9._:-]{1,128}$'),
  status varchar(16) NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Multiple keys may be active during a controlled rotation overlap.
-- Only public keys are stored; private signing keys remain on runner hosts.
CREATE TABLE IF NOT EXISTS runner_machine_keys (
  key_id varchar(128) PRIMARY KEY
    CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  runner_id uuid NOT NULL
    REFERENCES runner_machines(id) ON DELETE RESTRICT,
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  status varchar(16) NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'REVOKED')),
  valid_from timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT runner_machine_key_revocation_ck CHECK (
    (status = 'ACTIVE' AND revoked_at IS NULL)
    OR (status = 'REVOKED' AND revoked_at IS NOT NULL)
  ),
  CONSTRAINT runner_machine_key_validity_ck CHECK (
    expires_at IS NULL OR expires_at > valid_from
  )
);

CREATE INDEX IF NOT EXISTS idx_runner_machine_keys_by_runner
  ON runner_machine_keys (runner_id, status, valid_from);

CREATE TABLE IF NOT EXISTS runner_request_nonces (
  key_id varchar(128) NOT NULL
    REFERENCES runner_machine_keys(key_id) ON DELETE RESTRICT,
  nonce varchar(43) NOT NULL
    CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
  received_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (key_id, nonce),
  CONSTRAINT runner_request_nonce_expiry_ck CHECK (expires_at > received_at)
);

CREATE INDEX IF NOT EXISTS idx_runner_request_nonces_expiry
  ON runner_request_nonces (key_id, expires_at);

INSERT INTO schema_migrations (version, description)
VALUES (
  '0007_runner_machine_identity',
  'Per-runner public-key identities and replay-protected request nonces'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
