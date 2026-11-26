BEGIN;

-- Capability is provisioned by the control plane after runner qualification.
-- No v2 capability is granted by default or by runner self-registration.
CREATE TABLE IF NOT EXISTS runner_machine_protocol_capabilities (
  runner_id uuid NOT NULL
    REFERENCES runner_machines(id) ON DELETE RESTRICT,
  protocol_version varchar(8) NOT NULL
    CHECK (protocol_version IN ('v1', 'v2')),
  status varchar(16) NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'REVOKED')),
  qualification_reference varchar(256) NOT NULL
    CHECK (length(btrim(qualification_reference)) BETWEEN 1 AND 256),
  qualified_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (runner_id, protocol_version),
  CONSTRAINT runner_protocol_capability_revocation_ck CHECK (
    (status = 'ACTIVE' AND revoked_at IS NULL)
    OR (status = 'REVOKED' AND revoked_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_runner_protocol_capabilities_active
  ON runner_machine_protocol_capabilities (protocol_version, runner_id)
  WHERE status = 'ACTIVE' AND revoked_at IS NULL;

INSERT INTO schema_migrations (version, description)
VALUES (
  '0016_runner_protocol_capabilities',
  'Explicit control-plane-managed runner protocol qualification and revocation'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
