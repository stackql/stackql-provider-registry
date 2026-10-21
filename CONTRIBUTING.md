**Note**: 

- All contributions to the StackQL Provider Registry, through any means, are subject to the [license](/LICENSE). 
- Provider documents merged into this repository are signed with StackQL keys and published to the public registry used by every default configured `stackql` installation.  The review and CI requirements below are enforced for that reason.
- For how the registry is built, tested and published, see [docs/build-and-deployment.md](/docs/build-and-deployment.md).  For the signing scheme, see [docs/signing-and-verification.md](/docs/signing-and-verification.md).  For running the test suites locally, see [docs/test-developer-guide.md](/docs/test-developer-guide.md).

# Contribution flow

For a new provider, or a substantive change to an existing one (for example, regenerating a provider from a new upstream specification, or changing its authentication configuration), please raise an issue first and receive consensus that the work should proceed.  Targeted fixes to existing provider documents, such as a wrong path, a missing field or a response schema correction, can go straight to a pull request.

## Pull Requests

Please fork our repository and then raise a Pull Request (PR) against our `dev` branch.  Please add a fulsome description in the Pull Request comment: the provider(s) and service(s) changed, the source of the upstream specification where applicable, and evidence that the affected resources work (for example, `stackql` query output).  A usefully named feature branch for the PR source is appreciated.  We will attend to it and work with you as soon as possible.  

Once the PR is approved, we will sign any changed files, package for distribution and squash / merge the combined change set into the `dev` branch.  Once merged into `dev`, changes will instantly be available to `stackql` applications configured to integrate the `dev` registry.  After an additional period of monitoring from the team, it will be promoted to our main / production branch.  This equates to publication for default configured instances of `stackql`.

## Provider Document Requirements

Provider documents are signed and published by CI after merge, so the pipeline enforces the layout below and rejects anything else:

- documents live at `providers/src/<provider>/v00.00.00000/provider.yaml` and `providers/src/<provider>/v00.00.00000/services/<service>.yaml`, nothing else is permitted under the version directory
- provider directory names and service file names must start with a letter, digit or `_` and contain only letters, digits, `.`, `_` and `-`
- every entry must be a regular file or directory; symbolic links are not permitted anywhere under `providers/src`

The `v00.00.00000` directory name is a placeholder.  CI allocates the published version (`v<YY>.<MM>.<PR number>`) when the PR is built and stamps it into `provider.yaml`, so leave the directory name as is.

## CI Checks

Every PR to `dev` or `main` that touches `providers/src` runs the [Build and Deploy workflow](/.github/workflows/main.yml), which signs and packages the changed providers and runs end-to-end tests against them using [stackql-provider-tests](https://github.com/stackql/stackql-provider-tests).  The tests check that each document is a valid OpenAPI specification, that every service and resource is enumerable, and that `SELECT` and `INSERT` methods have valid response and request schemas.  See [provider tests](/docs/build-and-deployment.md#provider-tests-if-providers-were-updated) for details.  A PR will not be merged with failing tests.

A separate [provider delete guard](/docs/build-and-deployment.md#provider-delete-guard) fails any push or PR that removes a provider from `providers/src`.  If a removal is intentional, add the override token described there to the commit message.  Do not use `[skip ci]` on commits that touch `providers/src`, as it also skips the guard.

## Developing and Testing a Provider

Providers are generated from OpenAPI or Swagger specifications using [openapisaurus](https://github.com/stackql/openapisaurus); see [Developing a Provider](/README.md#developing-a-provider) in the README.  

To exercise a provider document before raising a PR, point `stackql` at your local checkout as an unsigned registry (this is the same configuration the repository's own robot tests use):

```bash
export LOCAL_REG="{ \"url\": \"file:///path/to/stackql-provider-registry/providers\", \"verifyConfig\": { \"nopVerify\": true } }"
./stackql --registry="${LOCAL_REG}" shell
```

Once merged into `dev`, the change can be verified against the `dev` registry:

```bash
export DEV_REG="{ \"url\": \"https://registry-dev.stackql.app/providers\" }"
./stackql --registry="${DEV_REG}" shell
```

## Changes to the Pipeline and Tooling

Changes outside `providers/src` (the GitHub Actions workflows, `scripts/`, the signing tool under `signing/` and the Cloudflare Worker under `origin/`) affect how every provider is published and served.  Please raise an issue to discuss these before opening a PR.  Security issues should not be raised as issues or PRs; see [SECURITY.md](/SECURITY.md).

Finally, in respect of all your efforts; we thank you and ask that you please give us a star while you are at it.

Many Thanks,

The StackQL team.
