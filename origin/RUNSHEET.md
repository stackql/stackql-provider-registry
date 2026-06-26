# Cutover run sheet

Ordered steps to deploy the Cloudflare green origin alongside the live Deno blue
origin, validate, and (later) cut over by DNS. The `stackql.app` zone is on
Cloudflare (account `4132d7d5587ee99b9d482ecfc2c1853c`).

## Safety invariant (holds until the Phase 4 cutover)

Merging this PR does NOT touch production traffic:

- The Deno steps in `main.yml` are unchanged - blue keeps deploying and serving.
- `wrangler.toml` route blocks are commented out, so `wrangler deploy` attaches
  no custom domains and makes no DNS changes. The green Worker is validated on its
  `*.workers.dev` URL - no temporary green DNS records are used.
- The existing DNS records are untouched: `registry.stackql.app` and
  `registry-dev.stackql.app` keep their A/AAAA records pointing at the Deno
  origin (`34.120.54.55` / `2600:1901:0:6d85::`).

So after merge, green runs fully in parallel; production still serves from Deno.
Cutover is a separate, deliberate DNS change in Phase 4, instantly reversible.

## A. Provision (local, on the feature branch) - me/you

1. `cd origin && npm install`
2. `npx wrangler login`
3. `bash bootstrap.sh`
   - creates R2 buckets `stackql-provider-registry-dev` + `stackql-provider-registry`
   - creates D1 `stackql-registry-analytics-dev` + `stackql-registry-analytics`
   - patches `wrangler.toml` with the real D1 IDs, applies `schema.sql` to both
   - (D1 IDs are not secrets; committing them to the public repo is expected)
4. `git --no-pager diff origin/wrangler.toml` - confirm `<DEV_D1_ID>` /
   `<PROD_D1_ID>` are replaced with UUIDs.

## B. Secrets (GitHub repo -> Settings -> Secrets and variables -> Actions)

| Secret | Value / source |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | `4132d7d5587ee99b9d482ecfc2c1853c` |
| `CLOUDFLARE_API_TOKEN` | API token, scopes below |
| `R2_ACCESS_KEY_ID` | from R2 -> Manage R2 API Tokens |
| `R2_SECRET_ACCESS_KEY` | from R2 -> Manage R2 API Tokens |

CLOUDFLARE_API_TOKEN scopes (one token, covers through Phase 4):

- Account / Workers Scripts / Edit
- Account / D1 / Edit
- Account / Workers R2 Storage / Edit
- Account / Account Settings / Read
- Zone / Workers Routes / Edit   (stackql.app) - needed when routes are uncommented
- Zone / DNS / Edit              (stackql.app) - custom-domain attach writes DNS
- Zone / Zone / Read             (stackql.app)

R2 API token (for `aws s3 sync`): R2 -> Manage R2 API Tokens -> Create -> permission
"Object Read & Write", scoped to the two buckets (or account-wide). Use the
returned Access Key ID / Secret Access Key as the two `R2_*` secrets.

## C. PR and merge

5. Commit `origin/` + the `main.yml` change, push the feature branch, open the PR.
   - PR CI runs build/sign/package/test only. Both the Deno deploy steps and the
     `[DEPLOY-CF]` steps are push-gated (`REG_EVENT == 'push'`), so nothing
     deploys on the PR itself.
6. Merge to `dev`. The push to `dev` runs, in the same job:
   - blue: deploy to `stackql-dev-registry` (Deno) - unchanged
   - green: `aws s3 sync` -> `stackql-provider-registry-dev` R2, then
     `wrangler deploy --env dev`

## D. Phase 3 validation (dev green, on workers.dev)

7. Find the dev Worker URL (`stackql-provider-registry-dev.<subdomain>.workers.dev`).
   Run the endpoint checks, byte-parity diff vs `https://registry-dev.stackql.app`,
   and a live pull (commands in `MIGRATION.md` Phase 3). Confirm D1 rows are
   written for `.tgz` and not for `providers.yaml`.
8. Merge `dev` -> `main`. The push to `main` deploys blue prod (Deno) and green
   prod (R2 `stackql-provider-registry` + `wrangler deploy --env production`).
   Validate prod green the same way on its workers.dev URL.

## E. Phase 4 cutover (separate change, after soak) - DNS last mile

Cut dev first, soak, then prod. For each hostname:

9. Dev: in Cloudflare DNS, delete the existing `registry-dev.stackql.app` A and
   AAAA records (they point at Deno), then attach `registry-dev.stackql.app` as a
   custom domain on the dev Worker - uncomment the dev route in `wrangler.toml`
   and `wrangler deploy --env dev`, or use the dashboard (Worker -> Settings ->
   Domains & Routes -> Add custom domain). Cloudflare creates the managed proxied
   record. Verify endpoint parity + live `REGISTRY PULL` against
   `https://registry-dev.stackql.app`. Soak.
10. Prod: repeat step 9 for `registry.stackql.app` on the production Worker.

Rollback (either hostname): detach the Worker custom domain and re-create the A
record `34.120.54.55` + AAAA `2600:1901:0:6d85::` (proxied) pointing back at Deno.
Blue is still deploying and serving throughout, so rollback is immediate with no
data loss.

## F. Phase 5 decommission (later, after stable soak)

See `MIGRATION.md` Phase 5: remove the Deno steps from `main.yml`, delete the
`_acme-challenge.registry*` CNAMEs, delete the Deno Deploy projects, revoke
`DENO_KV_ACCESS_TOKEN`, cancel the Deno subscription, archive `deno-deploy-registry`.
