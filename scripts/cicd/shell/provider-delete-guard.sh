#!/usr/bin/env bash
#
# provider-delete-guard.sh
#
# Fails if any provider directory under providers/src that exists in a base
# commit no longer exists in the head commit. A provider is considered present
# in a commit if providers/src/<provider>/<version>/provider.yaml exists for at
# least one version. Changes to files within a provider (including deletions
# of individual service docs) are not affected by this guard.
#
# Usage:
#   provider-delete-guard.sh <head-ref> <base-ref> [<base-ref> ...]
#
# Override:
#   A provider may be deleted only if a commit message in the range
#   <base-ref>..<head-ref> (or the head commit itself) contains an explicit
#   override token naming the provider(s) being deleted, for example:
#
#     [allow-provider-delete: netlify]
#     [allow-provider-delete: netlify, deno]
#
#   Wildcards are not supported; every deleted provider must be named.
#
# Exit codes:
#   0 - no providers deleted, or all deletions explicitly allowed
#   1 - one or more providers deleted without an override
#   2 - usage error

set -euo pipefail

PROVIDER_SRC="providers/src"
OVERRIDE_KEY="allow-provider-delete"

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <head-ref> <base-ref> [<base-ref> ...]" >&2
  exit 2
fi

head_ref="$1"
shift
base_refs=("$@")

log() { echo "[provider-delete-guard] $*"; }

summary() {
  # write to the GitHub Actions job summary when available, otherwise no-op
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "$*" >> "$GITHUB_STEP_SUMMARY"
  fi
}

resolve_commit() {
  git rev-parse --verify --quiet "${1}^{commit}"
}

# list providers present in a ref (one per line, sorted)
list_providers() {
  git ls-tree -r --name-only "$1" -- "$PROVIDER_SRC" \
    | grep -E "^${PROVIDER_SRC}/[^/]+/[^/]+/provider\.ya?ml$" \
    | awk -F/ '{print $3}' \
    | sort -u
}

# extract provider names named in override tokens from stdin
parse_overrides() {
  grep -oiE "\[[[:space:]]*${OVERRIDE_KEY}[[:space:]]*:[^]]*\]" \
    | sed -E "s/^\[[[:space:]]*[A-Za-z-]+[[:space:]]*://; s/\]$//" \
    | tr ',' ' ' \
    | tr -s '[:space:]' '\n' \
    | sed '/^$/d' \
    | sort -u
}

head_sha="$(resolve_commit "$head_ref")" || {
  echo "::error::head ref '${head_ref}' is not a commit" >&2
  exit 2
}

log "head: ${head_ref} (${head_sha})"

head_providers="$(list_providers "$head_sha")"
head_count="$(printf '%s\n' "$head_providers" | sed '/^$/d' | wc -l | tr -d ' ')"
log "providers in head: ${head_count}"

if [ "$head_count" -eq 0 ]; then
  echo "::error::no providers found under ${PROVIDER_SRC} in ${head_ref}; refusing to continue" >&2
  exit 1
fi

# collect override tokens from every commit reachable from head but not from
# any base, plus the head commit itself (covers merge/squash commits)
override_messages="$(git log -1 --format=%B "$head_sha")"
for base_ref in "${base_refs[@]}"; do
  base_sha="$(resolve_commit "$base_ref")" || continue
  override_messages+=$'\n'"$(git log --format=%B "${base_sha}..${head_sha}")"
done
allowed_providers="$(printf '%s\n' "$override_messages" | parse_overrides || true)"

if [ -n "$allowed_providers" ]; then
  log "override token(s) found for: $(printf '%s' "$allowed_providers" | tr '\n' ' ')"
fi

failed=0
deleted_any=0

for base_ref in "${base_refs[@]}"; do
  base_sha="$(resolve_commit "$base_ref")" || {
    log "base ref '${base_ref}' is not a commit, skipping"
    continue
  }

  if [ "$base_sha" = "$head_sha" ]; then
    log "base ${base_ref} is the head commit, skipping"
    continue
  fi

  base_providers="$(list_providers "$base_sha")"
  deleted="$(comm -23 <(printf '%s\n' "$base_providers") <(printf '%s\n' "$head_providers") | sed '/^$/d')"

  if [ -z "$deleted" ]; then
    log "no providers deleted relative to ${base_ref} (${base_sha})"
    continue
  fi

  deleted_any=1
  log "providers present in ${base_ref} (${base_sha}) but missing from head:"

  while IFS= read -r provider; do
    if printf '%s\n' "$allowed_providers" | grep -qxF "$provider"; then
      log "  ${provider} - deletion explicitly allowed by [${OVERRIDE_KEY}: ${provider}]"
      echo "::warning::provider '${provider}' deleted from ${PROVIDER_SRC} (explicitly allowed by override)"
      summary "- \`${provider}\` deleted from \`${PROVIDER_SRC}\` - allowed by override"
    else
      log "  ${provider} - deletion NOT allowed"
      echo "::error::provider '${provider}' was deleted from ${PROVIDER_SRC} without an override (base ${base_ref})"
      summary "- \`${provider}\` deleted from \`${PROVIDER_SRC}\` - **blocked** (no override)"
      failed=1
    fi
  done <<< "$deleted"
done

if [ "$failed" -ne 0 ]; then
  cat >&2 <<MSG

[provider-delete-guard] FAILED: one or more providers were deleted from ${PROVIDER_SRC}.

Provider deletions are blocked by default. If this deletion is intentional, add an
explicit override naming each deleted provider to a commit message in this push, e.g.

    [${OVERRIDE_KEY}: <provider>]
    [${OVERRIDE_KEY}: <provider-a>, <provider-b>]

and push again.
MSG
  exit 1
fi

if [ "$deleted_any" -eq 0 ]; then
  log "PASSED: no providers deleted"
  summary "Provider delete guard: no providers deleted from \`${PROVIDER_SRC}\`."
else
  log "PASSED: all provider deletions explicitly allowed"
fi
