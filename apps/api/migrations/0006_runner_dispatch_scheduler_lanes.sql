BEGIN;

-- A global sequence gives every served lane a unique, durable turn number.
-- This avoids timestamp ties causing the same student to win every poll.
CREATE SEQUENCE IF NOT EXISTS runner_dispatch_scheduler_ticket_seq
  AS bigint
  START WITH 1
  INCREMENT BY 1
  NO CYCLE;

-- One lane per tenant/student. A lane is served at most once per claim batch;
-- the earliest pending dispatch within that lane is selected first.
CREATE TABLE IF NOT EXISTS runner_dispatch_scheduler_lanes (
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  last_served_ticket bigint NOT NULL DEFAULT 0 CHECK (last_served_ticket >= 0),
  last_served_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, actor_user_id)
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_scheduler_fair_order
  ON runner_dispatch_scheduler_lanes (last_served_ticket, tenant_id, actor_user_id);

INSERT INTO schema_migrations (version, description)
VALUES (
  '0006_runner_dispatch_scheduler_lanes',
  'Durable per-student fair scheduling cursors for runner dispatch'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
