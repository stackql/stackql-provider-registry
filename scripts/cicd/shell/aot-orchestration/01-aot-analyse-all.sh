#!/usr/bin/env bash

CUR_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

REPOSITORY_ROOT="$(realpath "${CUR_DIR}/../../../..")"

anySdkCliPath="${1}"

for sd in ${REPOSITORY_ROOT}/providers/src/*/ ; do
    echo ""
    subdir="$(realpath "${sd}")"
    providerID="$(basename "${subdir}")"
    echo "Processing provider '${providerID}' at subdirectory: '${subdir}'" 1>&2
    echo ""
    for line in $(${anySdkCliPath} interrogate services ${REPOSITORY_ROOT}/providers ${subdir}/v00.00.00000/provider.yaml); do
        serviceIdentifier="${line}"
        ${REPOSITORY_ROOT}/scripts/cicd/shell/aot-analysis/01-aot-analysis-compact.sh ${anySdkCliPath} "${providerID}" "${subdir}/v00.00.00000/provider.yaml" "${serviceIdentifier}" &
        echo ""
    done
done

echo ""
echo "All tasks initiated. Waiting for them to complete..." 1>&2
echo ""

wait

echo ""
echo "All tasks completed." 1>&2
echo ""
