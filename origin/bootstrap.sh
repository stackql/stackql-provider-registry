#!/usr/bin/env bash
#
# One-time Cloudflare resource bootstrap for the registry origin Worker.
#
# Creates the R2 buckets and D1 databases, captures the D1 database IDs,
# patches wrangler.toml (replacing <DEV_D1_ID>/<PROD_D1_ID>), and applies the
# schema to both databases.
#
# Prereqs:
#   - run from the origin/ directory
#   - `npx wrangler login`  (or export CLOUDFLARE_API_TOKEN)
#   - Git Bash / any bash with sed + grep (no jq required)
#
# Safe to re-run: bucket creation is tolerated if the bucket already exists, and
# D1 IDs are looked up via `d1 info` if the database already exists.

set -euo pipefail

UUID_RE='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

get_d1_id () {
  local name="$1" id
  # try to create; pull the uuid out of the printed [[d1_databases]] snippet
  id=$(npx wrangler d1 create "$name" 2>&1 | grep -oiE "$UUID_RE" | head -1 || true)
  if [ -z "$id" ]; then
    # already exists (or output not parseable) -> look it up
    id=$(npx wrangler d1 info "$name" 2>&1 | grep -oiE "$UUID_RE" | head -1 || true)
  fi
  echo "$id"
}

echo "==> Creating R2 buckets (tolerated if they already exist)..."
npx wrangler r2 bucket create stackql-provider-registry-dev || true
npx wrangler r2 bucket create stackql-provider-registry || true

echo "==> Creating / resolving D1 databases..."
DEV_ID=$(get_d1_id stackql-registry-analytics-dev)
PROD_ID=$(get_d1_id stackql-registry-analytics)

[ -n "$DEV_ID" ]  || { echo "ERROR: could not resolve dev D1 id";  exit 1; }
[ -n "$PROD_ID" ] || { echo "ERROR: could not resolve prod D1 id"; exit 1; }
echo "    dev  D1 id: $DEV_ID"
echo "    prod D1 id: $PROD_ID"

echo "==> Patching wrangler.toml..."
sed -i.bak "s/<DEV_D1_ID>/$DEV_ID/g; s/<PROD_D1_ID>/$PROD_ID/g" wrangler.toml
rm -f wrangler.toml.bak

echo "==> Applying schema to both D1 databases (remote)..."
npx wrangler d1 execute stackql-registry-analytics-dev --remote --file=./schema.sql
npx wrangler d1 execute stackql-registry-analytics      --remote --file=./schema.sql

echo "==> Done. wrangler.toml changes:"
git --no-pager diff -- wrangler.toml || true
echo
echo "Next: commit the patched wrangler.toml, set the GitHub Actions secrets,"
echo "then push the branch and open the PR (see origin/RUNSHEET.md)."
