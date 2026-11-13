# Cloudflare Outbox Publisher Runtime

- Status: implementation prototype; not deployed.
- Transport: Cloudflare Queues, as accepted by ADR-0006.
- Publisher: the API Worker scheduled handler polls PostgreSQL outbox rows and sends metadata-only messages.

## Runtime behavior

- Cron trigger runs once per minute.
- Each invocation claims at most 10 rows with a 120-second lease.
- A successful queue send is followed by a fenced PostgreSQL acknowledgement.
- A queue-send failure releases the active lease with exponential retry timing.
- Retry delay starts at 5 seconds and is capped at 5 minutes.
- Queue send followed by lost acknowledgement can produce duplicate messages. Consumers must deduplicate by executionId.
- Worker logs contain only fixed error codes; queue payloads and student source are not logged.

## Configuration

The initial values are provisional operational defaults in wrangler.jsonc:
- Queue name: sky-high-execution-requests.
- Batch size: 10.
- Lease duration: 120 seconds.
- Retry base: 5 seconds.
- Retry cap: 5 minutes.

The publisher validates overrides and fails the scheduled cycle if invalid.

## Provisioning requirement

The queue itself is an external Cloudflare resource and has not been created by this repository change. Before deployment, create it in the intended Cloudflare account/environment using Wrangler or the dashboard, then configure the correct Hyperdrive binding and deploy the Worker. Do not deploy against the placeholder Hyperdrive ID.

## Not included

- Queue consumer, retry policy at the Cloudflare consumer, dead-letter queue or operator replay.
- Runner dispatch or execution.
- Production secrets, account IDs, queue IDs or Hyperdrive IDs.
- Proof of production delivery throughput or exactly-once delivery.

The next slice is a queue consumer that validates the small metadata envelope, claims the authoritative execution job in PostgreSQL, and safely handles duplicate deliveries. It must not execute student source in the Worker.
