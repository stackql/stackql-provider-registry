# Registry origin migration: Deno Deploy -> Cloudflare (blue-green)

Runbook for moving the registry origin from Deno Deploy (blue) to Cloudflare
Workers + R2 + D1 (green) without changing the client URL contract.

## URL contract (must not change)

- Production:  `https://registry.stackql.app`
- Development: `https://registry-dev.stackql.app`
- Paths: `/providers/dist/providers.yaml`, `/providers/dist/<provider>/<version>.tgz`,
  `/ping`, `/analytics`, `/analytics/last24hours`

Green is stood up on parallel hostnames first, then the real hostnames are
repointed by DNS (Phase 4). Rollback is reverting that DNS change.

## What is already in the repo (Phases 1-2, code complete)

- `origin/src/index.ts` - Worker port of the Deno origin, validated locally
  against all acceptance checks (routing, R2 serving, D1 logging).
- `origin/wrangler.toml` - `dev` and `production` environments, R2 + D1 bindings.
  Cutover hostnames are commented custom-domain routes; until the Phase 4 cutover
  the Worker is reachable on its `workers.dev` route (used for validation).
- `origin/schema.sql` - D1 `downloads` table + index.
- `.github/workflows/main.yml` - dual-publish steps (`[DEPLOY-CF] ...`) that sync
  docs to R2 and `wrangler deploy` the Worker, alongside the unchanged Deno steps.

Build / sign / package / test steps in `main.yml` are untouched.

## Phase 0: confirm inputs (do before deploying)

1. **DNS control of `stackql.app`.** Determine whether the zone is already on
   Cloudflare DNS.
   - If yes: Phase 4 is a custom-domain attach on the Worker (Cloudflare creates
     the proxied record automatically).
   - If no: either migrate the zone to Cloudflare, or keep DNS where it is and
     point the hostnames at the Worker via a CNAME to the Worker's
     `*.workers.dev` route / a Cloudflare custom domain. Custom domains require
     the zone to be on Cloudflare, so a zone migration is the clean path.
2. **S3 artifact bucket (`stackql-registry-artifacts`).** The Worker reads only
   from R2. Decide: keep S3 as the build archive (recommended - CI still
   publishes to it and the R2 sync is sourced from the assembled tree), or retire
   it later. No Worker change either way.
3. **Client default registry URL.** Confirm the deployed StackQL binaries already
   resolve to `https://registry.stackql.app/providers` (the `deno-deploy-registry`
   README noted this as a planned change). If clients already use the contract
   hostnames, the cutover is zero-client-change. If any client still points at
   `cdn.statically.io/...`, that is a separate client change and out of scope
   here - but note those clients will not follow the cutover.

## Phase 1: create Cloudflare resources

Authenticate wrangler (`wrangler login`, or set `CLOUDFLARE_API_TOKEN`).

```bash
cd origin
npm install

npx wrangler r2 bucket create stackql-provider-registry-dev
npx wrangler r2 bucket create stackql-provider-registry

npx wrangler d1 create stackql-registry-analytics-dev   # copy database_id
npx wrangler d1 create stackql-registry-analytics        # copy database_id

npx wrangler d1 execute stackql-registry-analytics-dev --remote --file=./schema.sql
npx wrangler d1 execute stackql-registry-analytics      --remote --file=./schema.sql
```

Then edit `wrangler.toml`: replace `<DEV_D1_ID>` and `<PROD_D1_ID>` with the
returned database IDs. CI cannot deploy until these are real.

Local acceptance (optional, already verified): see `origin/README.md`.

## GitHub Actions secrets required by the dual-path CI

Add these repo secrets (Settings -> Secrets and variables -> Actions):

| Secret                  | Purpose                                                        |
| ----------------------- | ------------------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`  | `wrangler deploy`. Scope: Workers Scripts edit, D1 edit, Workers R2 Storage edit, Account/Zone read. |
| `CLOUDFLARE_ACCOUNT_ID` | R2 S3 endpoint host and wrangler account.                     |
| `R2_ACCESS_KEY_ID`      | R2 S3 API token (R2 -> Manage API tokens) for `aws s3 sync`.  |
| `R2_SECRET_ACCESS_KEY`  | R2 S3 API secret.                                             |

These are independent of the existing AWS S3 credentials; the R2 sync steps
override the AWS env vars locally so they do not collide.

## Phase 2: dual-path CI (in place)

The `[DEPLOY-CF]` steps in `main.yml` run on push, gated on the same `dev`/`main`
split as the Deno steps:

- `dev` branch  -> R2 bucket `stackql-provider-registry-dev`, `wrangler deploy --env dev`
- `main` branch -> R2 bucket `stackql-provider-registry`,     `wrangler deploy --env production`

Acceptance: a push to `dev` updates both the dev Deno origin and the dev Worker
with byte-identical content (both sourced from the same assembled
`_deno_website/providers/dist` tree).

If you want to seed R2 once before the first CI push (so green is immediately
servable), run a one-off sync from a local checkout that has the full tree, or
trigger a `workflow_dispatch` / no-op push.

## Phase 3: validate green on the workers.dev URL

No temporary green DNS records are used. Each deployed Worker is reachable at its
`*.workers.dev` URL (dev: `stackql-provider-registry-dev.<subdomain>.workers.dev`,
prod: `stackql-provider-registry-prod.<subdomain>.workers.dev`). Validate there.

Run against the Worker URL:

```bash
BASE=https://stackql-provider-registry-dev.<subdomain>.workers.dev
curl -i $BASE/providers/dist/providers.yaml          # 200 text/plain
curl -i $BASE/providers/dist/aws/v0.1.3.tgz          # 200 application/gzip
curl -i $BASE/providers/dist/fred                     # 404
curl -i $BASE/ping                                    # 202 pong
curl -i $BASE/analytics                               # 200 text/html
curl -i $BASE/analytics/last24hours                  # 200 application/json
```

Byte parity vs blue (Deno):

```bash
GREEN=https://stackql-provider-registry-dev.<subdomain>.workers.dev
diff <(curl -s https://registry-dev.stackql.app/providers/dist/providers.yaml) \
     <(curl -s $GREEN/providers/dist/providers.yaml)
# repeat for a sample of .tgz using sha256sum
for v in aws/v0.1.3 ...; do
  a=$(curl -s https://registry-dev.stackql.app/providers/dist/$v.tgz | sha256sum)
  b=$(curl -s $GREEN/providers/dist/$v.tgz | sha256sum)
  [ "$a" = "$b" ] && echo "$v OK" || echo "$v MISMATCH"
done
```

Live pull from a StackQL client pointed at the Worker URL:

```bash
export STACKQL_REGISTRY='{"url": "https://stackql-provider-registry-dev.<subdomain>.workers.dev/providers"}'
stackql exec "REGISTRY PULL aws"
```

Analytics: confirm a `.tgz` pull writes one D1 row and `providers.yaml` writes
none, and that `/analytics` renders the three windows plus the 12-month matrix.

```bash
npx wrangler d1 execute stackql-registry-analytics-dev --remote \
  --command "SELECT count(*), provider FROM downloads GROUP BY provider"
```

Acceptance: full endpoint + pull parity, analytics writing correctly.

## Phase 4: DNS last mile (gated cutover)

Cut dev first, soak, then prod.

1. **Dev.** Attach `registry-dev.stackql.app` as a custom domain on the dev
   Worker. Either add it to `[env.dev]` routes in `wrangler.toml` (commented
   block is ready) and `wrangler deploy --env dev`, or attach via the dashboard
   (Workers -> the dev worker -> Settings -> Domains & Routes -> Add custom
   domain). Cloudflare repoints the proxied DNS record to the Worker.
   - Verify endpoint parity and a live `REGISTRY PULL` against
     `https://registry-dev.stackql.app`.
   - Soak.
2. **Prod.** Repeat for `registry.stackql.app` on the production Worker
   (`[env.production]` routes block, or dashboard). Verify parity + live pull.

**Rollback (either hostname):** detach the custom domain from the Worker / revert
the DNS record to the Deno origin. Blue is still live and still receiving CI
updates throughout the transition window, so rollback is immediate with no data
loss.

Acceptance: both production hostnames serve from the Worker with passing pull
tests; this rollback step is the documented procedure.

## Phase 5: decommission blue

Only after the soak window passes with green stable on the production hostnames:

1. In `main.yml`, remove the Deno steps:
   - `[DEPLOY] setup SSH`, `[DEPLOY] pull deno deploy assets`,
     `[DEPLOY] install deno`, `[DEPLOY] clean deploy dir`,
     `[DEPLOY] deploy to deno deploy (dev)`, `[DEPLOY] deploy to deno deploy (prod)`.
   - Keep `[DEPLOY] pull additional docs from artifact repo` (it assembles the
     full tree and regenerates `providers.yaml` that the R2 sync consumes).
   - Once `clean-deploy-dir.py` is no longer in the pipeline, `origin/` survives
     to the end of the job, so the `[DEPLOY-CF]` steps can move later if desired;
     no functional change needed.
   - Remove the `REG_DENO_DEPLOY_*` env vars.
2. Delete the Deno Deploy projects `stackql-registry` and `stackql-dev-registry`.
3. Revoke `DENO_KV_ACCESS_TOKEN` (the token in the old `deno-deploy-registry/env.sh`).
4. Cancel the Deno Deploy subscription.
5. Retire the `deno-deploy-registry` repo (archive).

Acceptance: CI deploys only to Cloudflare, no Deno dependency remains, the
registry serves entirely from the Worker.

## Notes / guardrails honored

- No secrets in the repo. `deno-deploy-registry/env.sh` is not carried across;
  `DENO_KV_ACCESS_TOKEN` is revoked in Phase 5. All credentials are GitHub
  Actions secrets / `wrangler secret`.
- Build/sign/package/test steps in `main.yml` are unchanged.
- Response paths, status codes, and content types match the Deno origin exactly
  (verified locally). Caching adds `Cache-Control` only: `immutable` long max-age
  on `.tgz`, `max-age=60` on `providers.yaml`.
- `dev` -> dev origin, `main` -> prod origin split preserved.

## Cost expectation

Within Workers free (100k req/day), R2 free (10GB storage, zero egress), and D1
free (5GB) at current volume. Moves to the $5/mo Workers plan plus R2 storage
overage only once those limits are exceeded. Immutable `.tgz` edge caching keeps
R2 read ops low.
