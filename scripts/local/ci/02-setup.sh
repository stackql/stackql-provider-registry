#!/usr/bin/env bash

>&2 echo "requires all of requirements.txt"

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

REPOSITORY_ROOT_DIR="$(realpath ${SCRIPT_DIR}/../../..)"

STACKQL_CORE_DIR="${REPOSITORY_ROOT_DIR}/stackql-core"

if [ ! -d "${STACKQL_CORE_DIR}/.venv" ]; then
  >&2 echo "No existing virtual environment, creating one..."
  >&2 echo "Creating virtual environment in ${STACKQL_CORE_DIR}/.venv"
  python -m venv "${STACKQL_CORE_DIR}/.venv"
  >&2 echo "Virtual environment created."
fi

source "${STACKQL_CORE_DIR}/.venv/bin/activate"

pip install -r "${STACKQL_CORE_DIR}/cicd/requirements.txt"

pip install -r "${REPOSITORY_ROOT_DIR}/requirements.txt"

cd "${STACKQL_CORE_DIR}"

python cicd/python/build.py --build

python test/python/stackql_test_tooling/registry_rewrite.py --srcdir "$(pwd)/test/registry/src" --destdir "$(pwd)/test/registry-mocked/src"

openssl req -x509 -keyout test/server/mtls/credentials/pg_server_key.pem -out test/server/mtls/credentials/pg_server_cert.pem -config test/server/mtls/openssl.cnf -days 365
openssl req -x509 -keyout test/server/mtls/credentials/pg_client_key.pem -out test/server/mtls/credentials/pg_client_cert.pem -config test/server/mtls/openssl.cnf -days 365
openssl req -x509 -keyout test/server/mtls/credentials/pg_rubbish_key.pem -out test/server/mtls/credentials/pg_rubbish_cert.pem -config test/server/mtls/openssl.cnf -days 365




