#!/usr/bin/env bash

CUR_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

REPOSITORY_ROOT="$(realpath "${CUR_DIR}/../../../..")"

anySdkExe="${1}"

providerID="${2}"

providerRootFile="${3}"

logDir="${REPOSITORY_ROOT}/test/log"

registryDir="${REPOSITORY_ROOT}/providers"

${anySdkExe} aot "${registryDir}" "${providerRootFile}" -v > "${logDir}/aot_${providerID}.log" 2>&1

rc="$?"

echo "${rc}" > "${logDir}/rc_aot_${providerID}.txt"