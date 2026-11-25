BEGIN;

-- The handoff repository validates v2 against execution_protocol_requests.
-- The existing dispatcher still claims v1 only, so widening this durable
-- metadata constraint does not make v2 work executable by a v1 runner.
ALTER TABLE runner_dispatch_outbox
  DROP CONSTRAINT IF EXISTS runner_dispatch_outbox_protocol_version_check;

ALTER TABLE runner_dispatch_outbox
  ADD CONSTRAINT runner_dispatch_outbox_protocol_version_check
  CHECK (protocol_version IN ('v1', 'v2'));

INSERT INTO schema_migrations (version, description)
VALUES (
  '0015_runner_dispatch_protocol_v2',
  'Allow validated protocol v2 durable handoff intents while dispatcher remains v1-only'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
