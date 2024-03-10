#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


_version="${1:-"v1"}"

_out_dir="${SCRIPT_DIR}/out"


#### https://blog.pinterjann.is/ed25519-certificates.html

CNF_FILE="openssl-ed25519.cnf"
CSR_FILE_NAME="stackql.io.csr"
PRIVATE_KEY_FILE_NAME="${_version}-private-key.pem"
PUBLIC_KEY_FILE_NAME="${_version}-public-key.pem"
SELF_SIGNED_CERT_FILE_NAME="${_version}-stackql-signing-bundle.pem"


openssl req -new -out ${_out_dir}/${CSR_FILE_NAME} -key ${SCRIPT_DIR}/${_version}/${PRIVATE_KEY_FILE_NAME} -config ${SCRIPT_DIR}/${CNF_FILE}

echo
echo "########################################################" 
echo "######### CSR DETAILS ##################################"
echo "########################################################"
echo

openssl req -in ${_out_dir}/${CSR_FILE_NAME} -text -noout

echo
echo "########################################################" 
echo "########################################################" 
echo "########################################################" 
echo

faketime '2024-01-31 08:15:42' openssl x509 -req -days 800 -in ${_out_dir}/${CSR_FILE_NAME} -signkey ${SCRIPT_DIR}/${_version}/${PRIVATE_KEY_FILE_NAME} -out ${_out_dir}/${SELF_SIGNED_CERT_FILE_NAME}

echo
echo "########################################################" 
echo "######### SELF SIGNED CERT DETAILS #####################"
echo "########################################################"
echo

openssl x509 -in ${_out_dir}/${SELF_SIGNED_CERT_FILE_NAME} -text -noout

echo
echo "########################################################" 
echo "########################################################" 
echo "########################################################" 
echo