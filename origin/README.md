# StackQL Provider Registry origin (Cloudflare Worker)

Origin server for the public StackQL provider registry, served from Cloudflare
Workers + R2 (docs) + D1 (download analytics). The URL contract is:

| Request                                    | Response                                              |
| ------------------------------------------ | ----------------------------------------------------- |
| `GET /providers/dist/providers.yaml`       | 200 `text/plain`, not logged                          |
| `GET /providers/dist/<provider>/<ver>.tgz` | 200 `application/gzip`, one download row written to D1 |
| `GET */ping`                               | 202 `pong`                                            |
| `GET /analytics`                           | 200 `text/html` dashboard (24h / 7d / 30d + 12-month matrix) |
| `GET /analytics/last24hours`               | 200 `application/json`                                |
| any other path                             | 404                                                   |
| any non-GET method                         | 405                                                   |

Docs are read from the R2 binding `REGISTRY_BUCKET` using the request path with
the leading slash stripped as the object key (`providers/dist/...`).
Analytics are written one row per `.tgz` pull to the D1 binding `ANALYTICS_DB`
inside `ctx.waitUntil`, so logging never adds latency to a pull.

## Layout

```
origin/
  wrangler.toml     two envs: dev (dev branch) and production (main branch)
  schema.sql        D1 downloads table + index
  src/index.ts      the Worker
  package.json      wrangler + types
```

## One-time resource bootstrap (Phase 1)

Run with a Cloudflare account that has Workers Paid or Free, R2, and D1 enabled.
Authenticate first with `wrangler login` (or set `CLOUDFLARE_API_TOKEN`).

```bash
cd origin
npm install

# R2 buckets (dev + prod)
npx wrangler r2 bucket create stackql-provider-registry-dev
npx wrangler r2 bucket create stackql-provider-registry

# D1 databases (dev + prod). Copy each returned database_id into wrangler.toml.
npx wrangler d1 create stackql-registry-analytics-dev
npx wrangler d1 create stackql-registry-analytics

# Apply the schema to both
npx wrangler d1 execute stackql-registry-analytics-dev --remote --file=./schema.sql
npx wrangler d1 execute stackql-registry-analytics      --remote --file=./schema.sql
```

After `d1 create`, replace `<DEV_D1_ID>` and `<PROD_D1_ID>` in `wrangler.toml`
with the returned database IDs.

## Local development

`wrangler dev` uses the top-level bindings (the dev R2 bucket and a local D1).
Seed a couple of objects into R2 (or local R2) and apply the schema locally:

```bash
cd origin
npm install
npx wrangler d1 execute stackql-registry-analytics-dev --local --file=./schema.sql

# seed a known object pair into the dev bucket so the endpoint checks pass
# (<docs-tree> is a local copy of the reconstructed registry docs tree, e.g. a
# `providers/dist` directory pulled from the artifact repository)
npx wrangler r2 object put stackql-provider-registry-dev/providers/dist/providers.yaml \
  --file=<docs-tree>/providers/dist/providers.yaml
npx wrangler r2 object put stackql-provider-registry-dev/providers/dist/aws/v0.1.3.tgz \
  --file=<docs-tree>/providers/dist/aws/v0.1.3.tgz

npm run dev
```

## Acceptance checks (Phase 1)

Against `http://localhost:8787` (wrangler dev) or a deployed hostname:

```bash
curl -i http://localhost:8787/providers/dist/providers.yaml      # 200 text/plain
curl -i http://localhost:8787/providers/dist/aws/v0.1.3.tgz       # 200 application/gzip
curl -i http://localhost:8787/providers/dist/fred                 # 404
curl -i http://localhost:8787/ping                                # 202 pong
curl -i http://localhost:8787/analytics                           # 200 text/html
curl -i http://localhost:8787/analytics/last24hours              # 200 application/json
curl -i -X POST http://localhost:8787/ping                        # 405
```

Note: `localhost` Host headers are intentionally not logged to D1. Test
analytics writes against a deployed hostname.

## Deploy

CI deploys automatically (see `.github/workflows/main.yml`): pushes to `dev`
deploy `--env dev`, pushes to `main` deploy `--env production`. Manual deploys:

```bash
npm run deploy:dev    # wrangler deploy --env dev
npm run deploy:prod   # wrangler deploy --env production
```
