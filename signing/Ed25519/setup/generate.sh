#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

## as per https://www.scottbrady91.com/openssl/creating-elliptical-curve-keys-using-openssl

# openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# openssl ec -in private-key.pem -pubout -out public-key.pem

# openssl req -new -x509 -key private-key.pem -out cert.pem -days 720

# ## as per https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html

# openssl pkeyutl -sign -in sample-file.txt -inkey private-key.pem -out sig

# openssl pkeyutl -verify -in sample-file.txt -sigfile sig -inkey private-key.pem


####




#### https://blog.pinterjann.is/ed25519-certificates.html

CNF_FILE="openssl-ed25519.cnf"
CSR_FILE_NAME="stackql.io.csr"
PRIVATE_KEY_FILE_NAME="ed25519-private-key.pem"
PUBLIC_KEY_FILE_NAME="ed25519-public-key.pem"
SELF_SIGNED_CERT_FILE_NAME="stackql.io.cert.pem"

openssl genpkey -algorithm Ed25519 -out ${SCRIPT_DIR}/${PRIVATE_KEY_FILE_NAME}

openssl pkey -in ${SCRIPT_DIR}/${PRIVATE_KEY_FILE_NAME} -pubout -out ${SCRIPT_DIR}/${PUBLIC_KEY_FILE_NAME}

openssl req -new -out ${SCRIPT_DIR}/${CSR_FILE_NAME} -key ${SCRIPT_DIR}/${PRIVATE_KEY_FILE_NAME} -config ${SCRIPT_DIR}/${CNF_FILE}

echo
echo "########################################################" 
echo "######### CSR DETAILS ##################################"
echo "########################################################"
echo

openssl req -in ${SCRIPT_DIR}/${CSR_FILE_NAME} -text -noout

echo
echo "########################################################" 
echo "########################################################" 
echo "########################################################" 
echo

openssl x509 -req -days 700 -in ${SCRIPT_DIR}/${CSR_FILE_NAME} -signkey ${SCRIPT_DIR}/${PRIVATE_KEY_FILE_NAME} -out ${SCRIPT_DIR}/${SELF_SIGNED_CERT_FILE_NAME}

echo
echo "########################################################" 
echo "######### SELF SIGNED CERT DETAILS #####################"
echo "########################################################"
echo

openssl x509 -in ${SCRIPT_DIR}/${SELF_SIGNED_CERT_FILE_NAME} -text -noout

echo
echo "########################################################" 
echo "########################################################" 
echo "########################################################" 
echo