#! /usr/bin/env bash

>&2 echo "cleaning dependent repositories from local file system"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

REPOSITORY_ROOT_DIR="$(realpath ${SCRIPT_DIR}/../../..)"

cd "${REPOSITORY_ROOT_DIR}"

rm -rf stackql-core    || true
rm -rf stackql-any-sdk || true

