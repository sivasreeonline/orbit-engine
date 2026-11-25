-- The durable handoff may store validated v2 intents, but the dispatcher
-- remains v1-only in every claim query.
DO $block$
DECLARE
  definition text;
BEGIN
  SELECT pg_get_constraintdef(oid)
    INTO definition
  FROM pg_constraint
  WHERE conrelid = 'runner_dispatch_outbox'::regclass
    AND conname = 'runner_dispatch_outbox_protocol_version_check';

  IF definition IS NULL OR definition NOT LIKE '%v1%' OR definition NOT LIKE '%v2%' THEN
    RAISE EXCEPTION 'runner dispatch protocol constraint does not allow v1 and v2';
  END IF;
END
$block$;
