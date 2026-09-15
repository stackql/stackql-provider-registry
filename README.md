<!-- language: lang-none -->
[![GitHub Actions](https://github.com/stackql/stackql-provider-registry/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/stackql/stackql-provider-registry/actions/workflows/main.yml)
![License](https://img.shields.io/github/license/stackql/stackql)

# StackQL Provider Registry

A repository of `provider` interface documents supporting [stackql](https://stackql.io/) ([stackql GitHub repo](https://github.com/stackql/stackql)). 

## Context


StackQL provider interface documents inform the stackql application on how to interact with a given provider (like `aws`, `azure`, `google`, etc), including what methods are available in the provider and how to invoke these using SQL semantics.  Provider interface documents are `yaml` formatted, OpenAPI specifications with extensions.  

The documents are versioned per provider in this repository, and built as signed and compressed packaged artifacts.  The packaged artifacts are registered and published to the StackQL Provider Registry Artifact Repository in AWS S3 (the master/archive store).  The full docs tree is then mirrored to Cloudflare R2 and served at the edge by a Cloudflare Worker (source in [origin/](origin/)), which provides the provider interface documents to the stackql application using the `REGISTRY LIST` and `REGISTRY PULL` commands.  

The following diagram shows the context of the provider registry:  

```mermaid
C4Context
    System_Ext(github_repo, "stackql-provider-registry", "GitHub Repository")
    System_Ext(github_actions, "Build and Deploy", "GitHub Actions")
    SystemDb(artifact_repo, "Artifact Repository", "AWS S3")
    SystemDb(r2_bucket, "Docs Mirror", "Cloudflare R2")
    System(cf_worker, "Provider Registry Origin", "Cloudflare Worker")
    System(stackql, "StackQL Application", "stackql")

    Rel(github_repo, github_actions, "triggers...")
    Rel(github_actions, artifact_repo, "registers and pushes to...", "signed tgz package")
    Rel(github_actions, r2_bucket, "syncs docs tree to...")
    Rel(cf_worker, r2_bucket, "reads provider docs from...")
    Rel(stackql, cf_worker, "list and pulls registry docs from...", "REGISTRY LIST | REGISTRY PULL")
    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="0")
```

The public StackQL Provider Registry is served from Cloudflare, using the following endpoints:  

| Endpoint | Description |
| --- | --- |
| [registry.stackql.app](https://registry.stackql.app/ping) | Production registry (built from `main`) |
| [registry-dev.stackql.app](https://registry-dev.stackql.app/ping) | Development registry (built from `dev`) |

## Contributing

Please see [.github/CONTRIBUTING.md](/.github/CONTRIBUTING.md).

## Developing a Provider

StackQL providers are generated from provider OpenAPI or Swagger specifications (either supplied by the provider or constituted through other scripts - for example, [google-discovery-to-openapi](https://github.com/stackql/google-discovery-to-openapi) or [stackql-azure-openapi](https://github.com/stackql/stackql-azure-openapi)).  

Once you have an OpenAPI specification, you can use the [openapisaurus](https://github.com/stackql/openapisaurus) utility project to generate a StackQL provider document.  

## Build and Deployment Workflow

The provider registry is built and deployed using GitHub Actions.  Provider documents are validated and tested in workflow steps and then packaged and stored in the artifact repository.  The reconstructed docs tree is mirrored to Cloudflare R2 and served by the Cloudflare Worker origin, where the provider documents are available from the `stackql` application using `REGISTRY LIST` or `REGISTRY PULL`.  See [docs/build-and-deployment.md](docs/build-and-deployment.md) for more information.  

A separate workflow guards against providers being deleted from `providers/src` on any push; intentional removals require an explicit override in the commit message. See [provider delete guard](docs/build-and-deployment.md#provider-delete-guard) for details.  

## Testing a Provider using the `dev` Registry

Use the following steps to test a provider using the `dev` registry:  

```bash
export DEV_REG="{ \"url\": \"https://registry-dev.stackql.app/providers\" }"
./stackql --registry="${DEV_REG}" shell
```