# ADR-0017: Layered Automated Security Scanning

- Status: Accepted
- Decision: Use GitHub CodeQL default setup for supported-language static analysis, Gitleaks for repository secret scanning, govulncheck for Go vulnerability reachability, Trivy for dependency/IaC/container scanning, npm audit for Node dependency advisories, and Dependabot for dependency update alerts.
- Rationale: These tools cover complementary risk classes and should run in CI rather than relying on developers to remember local commands.
- Supply-chain controls: Pin third-party GitHub Actions to full commit SHAs, keep workflow token permissions read-only unless a documented need exists, and avoid persisting checkout credentials.
- Policy: HIGH and CRITICAL Trivy findings fail the scan by default. Exceptions require evidence, an owner, justification and a review/expiry date.
- Limitations: Clean scanner output is not a security certification. M0 sandbox adversarial testing and production security review remain mandatory.
- Consequences: Scanner versions must be reviewed and updated deliberately. Public repository visibility does not justify publishing credentials, hidden assessments, customer/student data or production infrastructure secrets.
