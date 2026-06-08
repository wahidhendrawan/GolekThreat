# Security Policy

## Supported Versions

GolekThreat is currently pre-1.0. Security fixes are applied to the `main`
branch.

## Reporting a Vulnerability

Please do not open a public issue for sensitive vulnerabilities.

Report privately by contacting the repository owner through GitHub. Include:

- Affected component and version or commit.
- Reproduction steps.
- Impact and expected security boundary.
- Any suggested remediation.

For non-sensitive hardening suggestions, open a normal GitHub issue.

## Operational Notes

- The MVP does not include authentication or RBAC.
- Do not expose the app directly to the internet without adding authentication,
  TLS termination, and deployment hardening.
- Do not store real secrets in playbook notes, evidence, or `.env` files.
