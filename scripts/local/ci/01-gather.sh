#! /usr/bin/env bash

>&2 echo "requires git version >= 2.45"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

REPOSITORY_ROOT_DIR="$(realpath ${SCRIPT_DIR}/../../..)"

cd "${REPOSITORY_ROOT_DIR}"


# Check if the directory already exists
if [ -d "stackql-core" ]; then
  >&2 echo "Directory stackql-core already exists. Skipping clone."
  cd "${REPOSITORY_ROOT_DIR}/stackql-core"
  git pull origin main
  cd "${REPOSITORY_ROOT_DIR}"
else
  >&2 echo "Cloning stackql-core repository..."
  git clone --revision=refs/heads/main  https://github.com/stackql/stackql.git stackql-core
fi


# Check if the directory already exists
if [ -d "stackql-any-sdk" ]; then
  >&2 echo "Directory stackql-any-sdk already exists. Skipping clone."
  cd "${REPOSITORY_ROOT_DIR}/stackql-any-sdk"
  git pull origin main
  cd "${REPOSITORY_ROOT_DIR}"
else
  >&2 echo "Cloning stackql-any-sdk repository..."
  git clone --revision=refs/heads/main  https://github.com/stackql/any-sdk.git stackql-any-sdk
fi
