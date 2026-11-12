-- Acceptance test for durable per-student fair-scheduler cursor storage.
DO $block$
DECLARE
  first_ticket bigint;
  second_ticket bigint;
  lane_count integer;
BEGIN
  INSERT INTO runner_dispatch_scheduler_lanes (tenant_id, actor_user_id)
  VALUES (
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1',
    'ffffffff-ffff-4fff-8fff-fffffffffff1'
  )
  ON CONFLICT (tenant_id, actor_user_id) DO NOTHING;

  UPDATE runner_dispatch_scheduler_lanes
  SET last_served_ticket = nextval('runner_dispatch_scheduler_ticket_seq'),
      last_served_at = clock_timestamp(),
      updated_at = now()
  WHERE tenant_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1'
    AND actor_user_id = 'ffffffff-ffff-4fff-8fff-fffffffffff1'
  RETURNING last_served_ticket INTO first_ticket;

  UPDATE runner_dispatch_scheduler_lanes
  SET last_served_ticket = nextval('runner_dispatch_scheduler_ticket_seq'),
      last_served_at = clock_timestamp(),
      updated_at = now()
  WHERE tenant_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1'
    AND actor_user_id = 'ffffffff-ffff-4fff-8fff-fffffffffff1'
  RETURNING last_served_ticket INTO second_ticket;

  IF first_ticket IS NULL OR second_ticket IS NULL OR second_ticket <= first_ticket THEN
    RAISE EXCEPTION 'Scheduler tickets must increase monotonically';
  END IF;

  SELECT count(*) INTO lane_count
  FROM runner_dispatch_scheduler_lanes
  WHERE tenant_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1'
    AND actor_user_id = 'ffffffff-ffff-4fff-8fff-fffffffffff1';

  IF lane_count <> 1 THEN
    RAISE EXCEPTION 'Expected exactly one lane per tenant/student identity';
  END IF;
END
$block$;
