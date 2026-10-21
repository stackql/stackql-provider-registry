# Security Policy

The StackQL team takes the security of the StackQL Provider Registry seriously. Provider documents published from this repository are pulled and executed by every `stackql` installation, so a defect here can affect many users. We appreciate everyone who reports vulnerabilities responsibly, and we will do our best to acknowledge and address valid reports promptly.

## Reporting a Vulnerability

Please do not open a public GitHub issue or pull request for security reports. A public issue discloses the problem before a fix is available and puts users at risk.

Instead, report privately using GitHub private vulnerability reporting:

1. Open the [new advisory form](https://github.com/stackql/stackql-provider-registry/security/advisories/new) (Security tab -> Advisories -> "Report a vulnerability").
2. Provide as much detail as you can: the affected provider(s) and version(s) (as shown by `REGISTRY LIST`), reproduction steps, impact, and any suggested remediation.
3. Submit. This opens a private advisory thread visible only to you and the maintainers.

If you cannot use GitHub private vulnerability reporting, email us at [info@stackql.io](mailto:info@stackql.io). Please put "SECURITY" in the subject line and treat the contents as confidential.

## Supported Versions

The registry is a continuously published service rather than a versioned release. Each provider is published as an immutable, signed version (`v<YY>.<MM>.<PR number>`) when a change is merged, and the registry serves the latest published version of each provider by default.

Security fixes are published as a new version of the affected provider, first to the `dev` registry (`registry-dev.stackql.app`) and then to the production registry (`registry.stackql.app`). Previously published versions are not patched. To pick up a fix, pull the latest version of the affected provider:

```sql
REGISTRY PULL <provider>;
```

## Response Expectations

These are targets, not contractual guarantees:

- We aim to acknowledge a report within a few business days.
- We will keep you updated as we investigate and work on a fix.
- We will coordinate disclosure timing with you once a fix or mitigation is ready.

## Disclosure Policy

We follow coordinated (responsible) disclosure. Please give us a reasonable opportunity to release a fix before any public disclosure. We are happy to credit reporters in the advisory and release notes, unless you prefer to remain anonymous.

## Scope

This policy covers the contents of this repository and the services published from it:

- provider interface documents under `providers/src`, for example a document that directs `stackql` to send requests or credentials to an unintended host, misconfigures authentication, or maps a mutating API operation to a `SELECT` method
- the signing and verification tooling under `signing/`, including the embedded certificate bundles, and the build, packaging and publishing pipeline under `.github/workflows` and `scripts/`
- the registry origin: the Cloudflare Worker under `origin/` and the `registry.stackql.app` and `registry-dev.stackql.app` endpoints
- credentials or other secrets inadvertently committed to this repository

The following are out of scope for this repository and should be reported elsewhere:

- the `stackql` engine itself, including how it verifies and consumes registry documents: report via the [stackql](https://github.com/stackql/stackql/security/advisories/new) advisory form
- the request-execution library: report to [any-sdk](https://github.com/stackql/any-sdk)
- vulnerabilities in the third-party services that providers describe (for example, a cloud vendor's API): report those to the vendor. The registry only describes how to call these APIs.
