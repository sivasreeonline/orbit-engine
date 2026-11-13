# ADR-0010: Initial Runtime Families

- Status: Accepted
- Decision: Support Java 25 and Python 3.14 initially.
- Consequences: Pin patch versions and immutable runtime image digests; record runtime metadata per execution; use separate language-specific compile/run adapters.
- Open: exact maintained patch versions, base image and architecture support are selected during M0.
- Do not silently upgrade a runtime; use a documented compatibility change and regression suite.
