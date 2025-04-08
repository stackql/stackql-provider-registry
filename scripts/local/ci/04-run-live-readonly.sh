#!/usr/bin/env bash

>&2 echo "requires all of requirements.txt"

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

REPOSITORY_ROOT_DIR="$(realpath ${SCRIPT_DIR}/../../..)"

_SEC_FILE="${REPOSITORY_ROOT_DIR}/scripts/sec/sec-readwrite.sh"

if [ -f "${_SEC_FILE}" ]; then
  source "${_SEC_FILE}"
fi

if [ -f "scripts/sec/aws-ro-stackql.sh" ]; then
  source "scripts/sec/aws-ro-stackql.sh"
fi

if [ "${AWS_ACCESS_KEY_ID}" = "" ]; then
  >&2 echo "Required env var AWS_ACCESS_KEY_ID is not set"
  exit 1
fi

if [ "${AWS_SECRET_ACCESS_KEY}" = "" ]; then
  >&2 echo "Required env var AWS_SECRET_ACCESS_KEY is not set"
  exit 1
fi

if [ "${GOOGLE_CREDENTIALS}" = "" ]; then
  >&2 echo "Required env var GOOGLE_CREDENTIALS is not set"
  exit 1
fi

cd "${REPOSITORY_ROOT_DIR}"

source "${REPOSITORY_ROOT_DIR}/.venv/bin/activate"

robot -d test/robot/reports/readonly test/robot/stackql/live/readonly

