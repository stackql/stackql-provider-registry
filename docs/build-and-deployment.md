# Build and Deployment Workflow

The following diagram shows the CI/CD flow for this repository.  

```mermaid
  flowchart LR
  subgraph Actions[GitHub Actions - Build and Deploy]
    direction LR
    subgraph PR[triggered by pull request]
        Setup{{setup}} --> ProvUpd{providers\nupdated?}
        ProvUpd -->|yes| SignAndPackage{{ sign and\npackage\nartifacts }}
        SignAndPackage --> Tests[provider\ne2e tests]
    end
    subgraph Push[triggered by protected branch merge commit]
        Tests --> PushArtifacts[/register\nand publish\nartifacts to S3/]
        PushArtifacts --> SyncR2[/sync docs\nto R2/]
        SyncR2 --> Worker((Cloudflare\nWorker))
    end
    Worker --> End(end)
    ProvUpd -->|no| End
  end
```

The nodes in the above graph are described in the sections below:  

<!--ts-->
  * [setup](#setup)
  * [package artifacts](#package-artifacts)
  * [provider tests](#provider-tests)
  * [register and store artifacts](#register-and-store-artifacts)
  * [serve from Cloudflare](#serve-from-cloudflare)
<!--te-->

The following steps are performed on all pull requests to protected branches `dev` or `main` (if providers were updated):  

#### Setup

Pre workflow setup steps. Steps include:  

- `[SETUP] checkout repo`
- `[SETUP] setup job` - sets up job variables
- `[SETUP] print env vars`
- `[SETUP] get version` - gets the version of the provider(s) being updated
- `[SETUP] find changed files`
- `[SETUP] get updated providers`

#### Package Artifacts *(if providers were updated)*

Provider docs are signed and packaged for distribution, see [docs/signing-and-verification.md](signing-and-verification.md) for more specifics.  Steps include:  

- `[PACKAGE] set up golang`
- `[PACKAGE] build sign tool`
- `[PACKAGE] prepare dist and test dirs`
- `[PACKAGE] update versions` - update version in `provider.yaml` for updated providers to the version allocated earlier in the workflow
- `[PACKAGE] sign provider docs`
- `[PACKAGE] package provider docs`

#### Provider Tests *(if providers were updated)*

End-to-end tests will be performed on the new provider version using [stackql-provider-tests](https://github.com/stackql/stackql-provider-tests).  The following rules are evaluated:  

- [x] Document must be a valid OpenAPI specification
- [x] All services should be enumerable for resources
- [x] All resources should be enumerable for methods
- [x] Methods callable via `SELECT` must have a valid response schema
- [x] Methods callable via `INSERT` must have a valid request schema

Steps include:  

- `[TESTS] simulate REGISTRY PULL`
- `[TESTS] test provider(s)`

> The following steps are performed only on pushes to protected branches (merge commits) if providers were updated

#### Publish Artifacts to Provider Registry Artifact Repository

Packaged artifacts are published to the master/archive artifact repository in AWS S3 bucket (`stackql-registry-artifacts`). The full registry tree is then reconstructed from S3 so the complete set of provider docs (plus a freshly generated `providers.yaml`) is available for the serving layer. Steps include:  

- `[PUBLISH] configure aws credentials`
- `[PUBLISH] publish provider docs to artifact repo`
- `[DEPLOY] pull additional docs from artifact repo`

#### Serve from Cloudflare

S3 remains the master/archive store. The reconstructed docs tree is mirrored to Cloudflare R2, and a [Cloudflare Worker](../origin) (source in [origin/](../origin)) serves provider docs from R2 at the edge, logging download analytics to D1. Steps include:  

- `[DEPLOY-CF] install worker deps`
- `[DEPLOY-CF] sync docs to R2 (dev)` / `[DEPLOY-CF] sync docs to R2 (prod)`
- `[DEPLOY-CF] deploy worker (dev)` / `[DEPLOY-CF] deploy worker (prod)`

The public StackQL Provider Registry is served from Cloudflare, using the following endpoints:  

| Endpoint | Description |
| --- | --- |
| [registry.stackql.app](https://registry.stackql.app/ping) | Production registry (built from `main`) |
| [registry-dev.stackql.app](https://registry-dev.stackql.app/ping) | Development registry (built from `dev`) |
