#!/usr/bin/env bash

CUR_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

. ${CUR_DIR}/setup-env.sh

_private_key_env_var="${1:-"SIGNING_KEY_SECRET"}"
_signing_exe="${2:-"${REPOSITORY_ROOT_DIR}/ed25519tool"}"
_provider_root="${3:-"${REPOSITORY_ROOT_DIR}/providers/src"}"
_credentials_version="${3:-"v1"}"

find ${_provider_root} -type f -exec ${SCRIPT_DIR}/sign-file.sh "${_private_key_env_var}" "${_signing_exe}" {} "${_credentials_version}" \;