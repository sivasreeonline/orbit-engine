BEGIN;

-- Durable per-student scheduler cursor. One lane is served at most once in a
-- fair-dispatch batch; FIFO ordering is preserved within each lane.
CREATE TABLE IF NOT EXISTS runner_dispatch_scheduler_lanes (
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  last_served_at timestamptz NOT NULL DEFAULT 'epoch'::timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, actor_user_id)
);

CREATE INDEX IF NOT EXISTS idx_runner_dispatch_scheduler_fair_order
  ON runner_dispatch_scheduler_lanes (last_served_at, tenant_id, actor_user_id);

INSERT INTO schema_migrations (version, description)
VALUES (
  '0006_runner_dispatch_scheduler_lanes',
  'Durable per-student fair scheduling cursors for runner dispatch'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
