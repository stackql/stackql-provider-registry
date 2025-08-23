#!/usr/bin/env bash

CUR_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

REPOSITORY_ROOT="$(realpath "${CUR_DIR}/../../../..")"


rc='0'

for rcf in ${REPOSITORY_ROOT}/test/log/rc_* ; do 
    thisrc="$(cat "${rcf}")"
    if [ "$thisrc" != "0" ]; then
        echo "AOT analysis failure detected for: '${rcf}'" 1>&2
        rc='1'
    fi
done

if [ "$rc" != "0" ]; then
    echo "AOT analysis failures detected." 1>&2
    exit 1
fi

echo "All AOT analysis tasks completed successfully." 1>&2

