# Security Policy

Clay Seal Identity is security-critical software: it issues and verifies
cryptographically attested agent identities and Biscuit capability tokens. A
vulnerability here can undermine the trust of every system that relies on these
credentials. Please treat security reports with the appropriate care and report
them **privately** using the process below.

## Supported Versions

Security fixes are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

Older `0.3.x` and `0.4.x` releases predate the `clayseal` package rename and are
no longer maintained. Please upgrade to the latest `0.5.x` release before
reporting an issue.

## Reporting a Vulnerability

**Please do not open a public issue, pull request, or discussion for security
vulnerabilities.** Public disclosure before a fix is available puts every user
of Clay Seal Identity at risk.

Instead, report privately through GitHub's Private Vulnerability Reporting:

1. Go to the repository's **Security** tab:
   <https://github.com/clayseal/clayseal-identity/security>
2. Click **Report a vulnerability** to open a private security advisory.
3. Fill in the details described below.

This routes the report directly and privately to the maintainers via GitHub
Security Advisories. We do not use a separate security email address.

> **Maintainer note:** Private Vulnerability Reporting must be enabled for this
> mechanism to work. In the repository settings, under
> **Settings → Code security and analysis → Private vulnerability reporting**,
> enable the feature so the "Report a vulnerability" button appears on the
> Security tab.

### What to Include

To help us triage and reproduce quickly, please include as much of the following
as you can:

- A description of the vulnerability and its impact (e.g. credential forgery,
  token replay, signature bypass, key exposure, privilege escalation).
- The affected version(s), commit, and component (SDK, FastAPI service, CLI,
  Biscuit handling, etc.).
- Step-by-step reproduction instructions or a minimal proof-of-concept.
- Any relevant configuration (e.g. signing algorithm, KMS provider, trust
  domain) with secrets redacted.
- Your assessment of severity and any suggested remediation, if you have one.

Please **do not include real secrets, private keys, or production credentials**
in your report; redact or use dummy values.

## Response Expectations

- **Acknowledgement:** We aim to acknowledge your report within **3 business
  days**.
- **Assessment:** We will confirm the vulnerability, determine affected
  versions, and share an initial assessment and remediation plan.
- **Updates:** We will keep you informed of progress toward a fix as we work
  through it.

## Coordinated Disclosure

We follow a coordinated-disclosure approach:

- Please give us a reasonable opportunity to investigate and release a fix
  before any public disclosure.
- We will work with you on a disclosure timeline and coordinate the release of a
  patched version and a published advisory.
- With your permission, we are happy to credit you for the discovery in the
  advisory and release notes.

Thank you for helping keep Clay Seal Identity and its users safe.
