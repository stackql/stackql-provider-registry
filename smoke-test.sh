#!/usr/bin/env bash
#
# smoke-test.sh - manual smoke test for the StackQL provider registry origin.
#
# Exercises every route in the URL contract plus live stackql registry
# list/pull, against dev and prod on BOTH the workers.dev hostnames and the
# production DNS names. This is run by hand, NOT in CI:
#
#   bash smoke-test.sh
#
# Override the workers.dev subdomain if yours differs:
#   CF_WORKERS_SUBDOMAIN=myacct bash smoke-test.sh
#
# Note: pulling a provider and fetching a .tgz both write a row to the D1
# analytics table by design, so running this adds to the download counts.
#
# Exit code: 0 if all tests pass, 1 if any fail.

set -uo pipefail

SUBDOMAIN="${CF_WORKERS_SUBDOMAIN:-javen3010}"
CURL="curl -s --max-time 30"

# colors only when stdout is a terminal
if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; BOLD=''; NC=''
fi

PASS=0; FAIL=0; SKIP=0
declare -a FAILURES=()

pass() { PASS=$((PASS+1)); printf "  ${GREEN}PASS${NC} %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); FAILURES+=("$1"); printf "  ${RED}FAIL${NC} %s\n" "$1"; }
skip() { SKIP=$((SKIP+1)); printf "  ${YELLOW}SKIP${NC} %s\n" "$1"; }

# --- HTTP helpers ---------------------------------------------------------

status_of() { $CURL -o /dev/null -w '%{http_code}' "$@"; }
ctype_of()  { $CURL -o /dev/null -w '%{content_type}' "$@"; }
headers_of(){ $CURL -D - -o /dev/null "$@"; }   # GET, dump response headers

expect_status() { # desc expected url [extra curl args...]
  local desc="$1" exp="$2" url="$3"; shift 3
  local got; got=$(status_of "$@" "$url")
  if [ "$got" = "$exp" ]; then pass "$desc -> $got"; else fail "$desc -> expected $exp, got $got"; fi
}

expect_ctype() { # desc url substring
  local desc="$1" url="$2" want="$3" got
  got=$(ctype_of "$url")
  case "$got" in *"$want"*) pass "$desc -> $got";; *) fail "$desc -> expected ~$want, got '${got:-<none>}'";; esac
}

expect_body() { # desc url substring
  local desc="$1" url="$2" want="$3" body
  body=$($CURL "$url")
  case "$body" in *"$want"*) pass "$desc";; *) fail "$desc -> body missing '$want'";; esac
}

expect_header() { # desc url substring (case-insensitive)
  local desc="$1" url="$2" want="$3"
  if headers_of "$url" | grep -iq -- "$want"; then pass "$desc"; else fail "$desc -> header missing '$want'"; fi
}

aws_latest_version() { # base -> latest aws version, e.g. v26.05.00395
  $CURL "$1/providers/dist/providers.yaml" | awk '
    /^  aws:/                  {f=1; next}
    f && /^  [A-Za-z0-9_.]+:/  {f=0}
    f && /^    - /             {sub(/^[[:space:]]*-[[:space:]]*/,""); v=$0}
    END{print v}'
}

run_http_suite() { # label base
  local label="$1" base="$2"
  printf "\n${BOLD}HTTP: %s${NC}  %s\n" "$label" "$base"

  # served by Cloudflare (Worker / workers.dev both emit these)
  expect_header "served by Cloudflare (server header)" "$base/ping" "server: cloudflare"
  expect_header "served by Cloudflare (cf-ray header)" "$base/ping" "cf-ray:"

  # ping/pong (202, body "pong")
  expect_status "GET /ping" 202 "$base/ping"
  local pong; pong=$($CURL "$base/ping")
  if [ "$pong" = "pong" ]; then pass "GET /ping body == pong"; else fail "GET /ping body == pong (got '${pong}')"; fi

  # providers.yaml: 200 text/plain, body starts providers:, short cache
  expect_status "GET providers.yaml" 200 "$base/providers/dist/providers.yaml"
  expect_ctype  "GET providers.yaml content-type" "$base/providers/dist/providers.yaml" "text/plain"
  expect_body   "GET providers.yaml body has providers:" "$base/providers/dist/providers.yaml" "providers:"
  expect_header "GET providers.yaml cache-control max-age=60" "$base/providers/dist/providers.yaml" "max-age=60"

  # a real .tgz: 200 application/gzip + immutable cache-control (one download, parsed)
  local ver tgz resp st ct
  ver=$(aws_latest_version "$base")
  if [ -n "$ver" ]; then
    tgz="$base/providers/dist/aws/${ver}.tgz"
    resp=$($CURL -D - -o /dev/null -w $'\n__STATUS__%{http_code}\n__CTYPE__%{content_type}' "$tgz")
    st=$(printf '%s' "$resp" | grep -o '__STATUS__[0-9]*' | sed 's/__STATUS__//')
    ct=$(printf '%s' "$resp" | sed -n 's/.*__CTYPE__//p')
    if [ "$st" = "200" ]; then pass "GET aws/${ver}.tgz -> 200"; else fail "GET aws/${ver}.tgz -> ${st:-<none>}"; fi
    case "$ct" in *application/gzip*) pass "GET aws .tgz content-type -> $ct";; *) fail "GET aws .tgz content-type -> '${ct:-<none>}'";; esac
    if printf '%s' "$resp" | grep -iq immutable; then pass "GET aws .tgz immutable cache-control"; else fail "GET aws .tgz immutable cache-control"; fi
  else
    fail "could not resolve aws version from providers.yaml"
  fi

  # 404 (unknown doc) and 405 (non-GET)
  expect_status "GET unknown doc" 404 "$base/providers/dist/does-not-exist"
  expect_status "POST /ping" 405 "$base/ping" -X POST

  # analytics
  expect_status "GET /analytics" 200 "$base/analytics"
  expect_ctype  "GET /analytics content-type" "$base/analytics" "text/html"
  expect_body   "GET /analytics renders dashboard" "$base/analytics" "StackQL Registry Analytics"
  expect_status "GET /analytics/last24hours" 200 "$base/analytics/last24hours"
  expect_ctype  "GET /analytics/last24hours content-type" "$base/analytics/last24hours" "application/json"
  local j; j=$($CURL "$base/analytics/last24hours")
  case "$j" in \{*|\[*) pass "GET /analytics/last24hours is JSON";; *) fail "GET /analytics/last24hours not JSON ('${j:0:40}')";; esac
}

run_stackql_suite() { # label base
  local label="$1" base="$2"
  printf "\n${BOLD}stackql: %s${NC}  %s\n" "$label" "$base"
  if [ -z "$STACKQL" ]; then
    skip "[$label] stackql registry list (no stackql binary)"
    skip "[$label] stackql registry pull aws (no stackql binary)"
    return
  fi
  local reg="{ \"url\": \"$base/providers\" }" out
  if out=$("$STACKQL" --registry="$reg" exec "registry list" 2>&1) && printf '%s' "$out" | grep -q "aws"; then
    pass "[$label] stackql registry list"
  else
    fail "[$label] stackql registry list"
  fi
  if out=$("$STACKQL" --registry="$reg" exec "registry pull aws" 2>&1) && printf '%s' "$out" | grep -q "successfully installed"; then
    pass "[$label] stackql registry pull aws"
  else
    fail "[$label] stackql registry pull aws"
  fi
}

# --- preflight: stackql ---------------------------------------------------

printf "${BOLD}Preflight${NC}\n"
STACKQL=""
if [ -x ./stackql ]; then
  STACKQL=./stackql
elif command -v stackql >/dev/null 2>&1; then
  STACKQL=$(command -v stackql)
else
  printf "  stackql not found in cwd; installing via get-stackql.io...\n"
  curl -fsSL https://get-stackql.io/install | sh || true
  if [ -x ./stackql ]; then STACKQL=./stackql
  elif command -v stackql >/dev/null 2>&1; then STACKQL=$(command -v stackql); fi
fi
if [ -n "$STACKQL" ]; then
  printf "  using stackql: %s\n" "$STACKQL"
else
  printf "  ${YELLOW}stackql unavailable - stackql tests will be skipped${NC}\n"
fi

# --- targets (label|base) -------------------------------------------------

TARGETS=(
  "dev  workers.dev|https://stackql-provider-registry-dev.${SUBDOMAIN}.workers.dev"
  "prod workers.dev|https://stackql-provider-registry-prod.${SUBDOMAIN}.workers.dev"
  "dev  dns        |https://registry-dev.stackql.app"
  "prod dns        |https://registry.stackql.app"
)

for entry in "${TARGETS[@]}"; do
  run_http_suite "${entry%%|*}" "${entry#*|}"
done

for entry in "${TARGETS[@]}"; do
  run_stackql_suite "${entry%%|*}" "${entry#*|}"
done

# --- summary --------------------------------------------------------------

printf "\n${BOLD}==== SUMMARY ====${NC}\n"
printf "  ${GREEN}PASS${NC}: %d\n" "$PASS"
printf "  ${RED}FAIL${NC}: %d\n" "$FAIL"
[ "$SKIP" -gt 0 ] && printf "  ${YELLOW}SKIP${NC}: %d\n" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  printf "\n${RED}Failures:${NC}\n"
  for f in "${FAILURES[@]}"; do printf "  - %s\n" "$f"; done
  exit 1
fi
printf "\n${GREEN}All tests passed.${NC}\n"
exit 0
