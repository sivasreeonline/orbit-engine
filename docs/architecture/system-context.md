# System Context

## Actors
- Student: browses problem, edits source, runs sample/public tests, submits official solution, reviews history and feedback.
- Trainer: creates/publishes assessments, monitors submissions, reviews individual evidence and batch performance.
- Platform administrator: configures approved runtimes, resource policies, problem versions and operational controls.

## Trust boundaries
1. Browser to Cloudflare API: authenticated, validated requests; browser is untrusted.
2. API/control plane to queue: authenticated job dispatch; messages are untrusted until validated.
3. Runner control plane to sandbox: strong isolation boundary; submitted program is hostile.
4. Runner to database/object storage: authenticated service identity and narrowly scoped permissions.
5. AI provider boundary: send only necessary evidence; treat generated output as untrusted advice.

## Main flow
Student browser -> Workers API -> Neon transaction + outbox -> Queue -> Go runner -> isolated OCI/gVisor sandbox -> runner result -> assessment persistence -> API result -> browser.

PostgreSQL is authoritative. Queue and Durable Object state are coordination mechanisms. R2 stores larger immutable artifacts. Hidden tests remain server-side and are never included in student-visible responses.
