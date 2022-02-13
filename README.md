
# StackQL Provider Registry

A repository of `provider` interface documents supporting [stackql](https://stackql.io/) ([github](https://github.com/stackql/stackql)). 

## Current Providers

- Google.
- Okta.

## Signing and verification

See [docs/signing-and-verification.md](/docs/signing-and-verification.md).

To build the signing and verification tool:

```
go build -o ed25519tool ./signing/Ed25519/app/cmd/main
```

Then:

```bash
CREDENTIALS_DIR="${HOME}/stackql/stackql-provider-registry/signing/Ed25519/setup/scratchpad"
TESTING_INPUT_DIR="${HOME}/stackql/stackql-provider-registry/signing/Ed25519/test"
TESTING_OUTPUT_DIR="${CREDENTIALS_DIR}"

PRIVATE_KEY_FILE="sample-ed25519-private-key.pem"

PUBLIC_KEY_FILE="sample-ed25519-public-key.pem"

CERT_FILE="sample-ed25519-cert.pem"

CSR_FILE="sample-ed25519.csr"



./ed25519tool createkeys ${CREDENTIALS_DIR}/${PRIVATE_KEY_FILE} ${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${CREDENTIALS_DIR}/${CERT_FILE} ${CREDENTIALS_DIR}/${CSR_FILE}


./ed25519tool sign --privatekeypath=${CREDENTIALS_DIR}/${PRIVATE_KEY_FILE} --signaturetime="Jan 2 15:04:05 2006" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/old-timestamp-sample-infile.txt.sig

./ed25519tool sign --privatekeypath=${CREDENTIALS_DIR}/${PRIVATE_KEY_FILE} --signaturetime="Jan 2 15:04:05 2023" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.embedded.sig

./ed25519tool sign --privatekeypath=${CREDENTIALS_DIR}/${PRIVATE_KEY_FILE} --signaturetime="Jan 2 15:04:05 2033" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/future-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/old-timestamp-sample-infile.txt.sig

## should and will fail with timestamp message
./ed25519tool certverify --certificatepath=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/old-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool certverify --certificatepath=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig


## will fail due to self-signed certificate in strict mode
./ed25519tool certverify --certificatepath=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt --strict=true ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/future-timestamp-sample-infile.txt.sig

## should and will fail with timestamp message
./ed25519tool certverify --certificatepath=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/future-timestamp-sample-infile.txt.sig

```
