#!/usr/bin/env bash

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


_private_key_env_var="${1}"
_signing_exe="${2}"
_file_to_sign="${3}"
_credentials_version="${4:-"v1"}"


echo "checking ${_file_to_sign}"
_yaml_fn=$(echo "${_file_to_sign}" | grep -E '.*(\.yaml|\.json)$')
if [ "${_yaml_fn}" != "" ]; then
  echo "signing ${_file_to_sign}"
  ${_signing_exe} sign --privatekeyenvvar=${_private_key_env_var} "${_file_to_sign}" -o "${_file_to_sign}.sig"
fi