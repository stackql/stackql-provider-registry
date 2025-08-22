#!/usr/bin/env bash

CUR_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

REPOSITORY_ROOT="$(realpath "${CUR_DIR}/../../../..")"

anySdkExe="${1}"

providerID="${2}"

providerRootFile="${3}"

serviceIdentifier="${4}"

logDir="${REPOSITORY_ROOT}/test/log"

registryDir="${REPOSITORY_ROOT}/providers"

if [ "${serviceIdentifier}" != "" ]; then
  ${anySdkExe} aot "${registryDir}" "${providerRootFile}" "${serviceIdentifier}" -v > "${logDir}/aot_${providerID}_${serviceIdentifier}.log" 2>&1
else
  ${anySdkExe} aot "${registryDir}" "${providerRootFile}" -v > "${logDir}/aot_${providerID}.log" 2>&1
fi

rc="$?"

if [ "${serviceIdentifier}" != "" ]; then
  echo "${rc}" > "${logDir}/rc_aot_${providerID}_${serviceIdentifier}.txt"
  echo "${SECONDS}" > "${logDir}/duration_seconds_aot_${providerID}_${serviceIdentifier}.txt"
else
  echo "${rc}" > "${logDir}/rc_aot_${providerID}.txt"
  echo "${SECONDS}" > "${logDir}/duration_seconds_aot_${providerID}.txt"
fi