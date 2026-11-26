# M0 Runner Contract Skeleton

## Scope
The first Go runner commit is a contract and process-health skeleton only. It does not execute programs, start child processes, connect to queues, access storage or expose submission endpoints.

## Safety behavior
- Listener defaults to 127.0.0.1:8080.
- Non-loopback bind addresses are rejected until authenticated private service transport exists.
- GET /healthz returns process health only.
- GET /readyz returns 503 with sandbox_executor_not_configured.
- The only executor implementation fails closed with ErrSandboxNotConfigured.
- Request types refer to opaque source artifact and test bundle IDs. They do not embed code or test data.
- Structural validation requires version, IDs, action, language, runtime, 64-digit SHA-256 and positive resource limits.

## Not yet implemented
- Queue or pull consumer.
- Service-to-service authentication.
- Artifact retrieval and hash verification.
- Runtime image resolution.
- OCI/gVisor invocation.
- Resource enforcement and network isolation.
- Test harness and verdict calculation.
- Result persistence, retry or cancellation.

These must be implemented and tested in the M0 sequence. Health success does not imply readiness or production safety.
