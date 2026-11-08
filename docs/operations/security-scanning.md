# Security Scanning

This repository uses layered, automated security checks. No single scanner proves that the application is secure.

## Enabled checks

| Tool | What it checks | When it runs |
|---|---|---|
| GitHub CodeQL default setup | Supported-language static analysis | Managed by GitHub on the default branch and eligible pull requests |
| Gitleaks | Secrets in changed commits and repository history | Pull requests, pushes to main, weekly schedule, manual dispatch |
| govulncheck | Known Go vulnerabilities reachable from the Go source call graph | Go module changes, pushes to main, weekly schedule, manual dispatch |
| Trivy filesystem | Dependency vulnerabilities and infrastructure misconfiguration | Relevant pull requests, pushes to main, weekly schedule, manual dispatch |
| Trivy image | Vulnerabilities in the runner container image | Automatically after services/execution-runner/Dockerfile exists |
| npm audit | Node dependency advisories | Frontend CI |
| Dependabot | Dependency update and vulnerability alerts | GitHub-managed; configuration is in .github/dependabot.yml |

## Supply-chain controls

- Third-party GitHub Actions in the security workflows are pinned to full commit SHAs.
- Workflows use read-only repository permissions.
- Checkout does not persist the repository token in the workspace.
- Gitleaks PR comments are disabled to avoid granting pull-request write access.
- govulncheck is installed/run at the pinned module version v1.9.0.
- Trivy fails the job for HIGH and CRITICAL findings; exceptions must be reviewed rather than silently ignored.
- Container scanning is skipped, with an explicit notice, until the runner Dockerfile is introduced.

## Handling findings

### Exposed secret
1. Treat the credential as compromised immediately.
2. Revoke or rotate it with its issuing provider.
3. Review provider audit logs for unauthorized use.
4. Remove it from active source and configuration.
5. If it exists in Git history, coordinate history cleanup and invalidate affected clones/forks where practical.
6. Never paste the secret into an issue, pull request or chat.

Deleting a secret in a later commit does not make the earlier Git object safe.

### Dependency vulnerability
1. Confirm whether the vulnerable package/version is actually used.
2. Upgrade to a compatible patched release.
3. Run unit, integration and security tests.
4. Record a time-bounded exception only when no safe upgrade exists.
5. Do not suppress a finding solely to make CI green.

### Container finding
1. Identify the affected OS package or application dependency.
2. Prefer a patched base image or dependency version.
3. Rebuild using pinned runtime versions and immutable image references.
4. Re-run Trivy and M0 sandbox regression tests.

## Important boundaries

- CodeQL, Gitleaks, govulncheck, Trivy and npm audit detect different classes of issues.
- A clean scan is not proof against zero-days, sandbox escapes, logic flaws or insecure deployment configuration.
- Gitleaks is not a substitute for GitHub secret scanning and push protection. Enable GitHub's native secret scanning/push protection where available.
- Trivy container scanning does not prove gVisor isolation. M0 adversarial sandbox tests remain mandatory.
- Security alerts and build failures require human review; AI-generated fixes must not auto-merge into security-sensitive code.
