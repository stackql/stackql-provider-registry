
# Working with the command line tool

To build the signing and verification tool:

```
go build -o ed25519tool ./signing/Ed25519/app/cmd/main
```

Then, from the repository root directory:

```bash
. ./scripts/setup-env.sh

CREDENTIALS_DIR="${REPOSITORY_ROOT_DIR}/signing/Ed25519/setup/scratchpad"
TESTING_INPUT_DIR="${REPOSITORY_ROOT_DIR}/signing/Ed25519/test"
TESTING_OUTPUT_DIR="${CREDENTIALS_DIR}"

PRIVATE_KEY_FILE="smoke-testing-private-key.pem"

PUBLIC_KEY_FILE="smoke-testing-public-key.pem"

CERT_FILE="smoke-testing-cert.pem"

CSR_FILE="smoke-testing.csr"

## Create key pair and cert
./ed25519tool createkeys ${CREDENTIALS_DIR}/${PRIVATE_KEY_FILE} ${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${CREDENTIALS_DIR}/${CERT_FILE} ${CREDENTIALS_DIR}/${CSR_FILE}

## Store the private key in an env var
SIGNING_KEY_SECRET=$(cat ${CREDENTIALS_DIR}/${PRIVATE_KEY_FILE})

## Sign some files
./ed25519tool sign --privatekeyenvvar="SIGNING_KEY_SECRET" --signaturetime="Jan 2 15:04:05 2006" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/old-timestamp-sample-infile.txt.sig

./ed25519tool sign --privatekeyenvvar="SIGNING_KEY_SECRET"  --signaturetime="Jan 2 15:04:05 2023" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

./ed25519tool sign --privatekeyenvvar="SIGNING_KEY_SECRET"  --signaturetime="now" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/now-timestamp-sample-infile.txt.sig

./ed25519tool sign --privatekeyenvvar="SIGNING_KEY_SECRET"  --signaturetime="Jan 2 15:04:05 2033" ${TESTING_INPUT_DIR}/sample-infile.txt -o ${TESTING_OUTPUT_DIR}/future-timestamp-sample-infile.txt.sig

## Now, verify

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/old-timestamp-sample-infile.txt.sig

## should and will fail with timestamp message
./ed25519tool certverify --localcerts.signingbundle=${CREDENTIALS_DIR}/${CERT_FILE} --localcerts.cabundle=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/old-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool certverify --localcerts.signingbundle=${CREDENTIALS_DIR}/${CERT_FILE} --localcerts.cabundle=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/now-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool certverify --localcerts.signingbundle=${CREDENTIALS_DIR}/${CERT_FILE} --localcerts.cabundle=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/now-timestamp-sample-infile.txt.sig


## all good with self signed CA if we supply it as a command line arg
./ed25519tool certverify --localcerts.signingbundle=${CREDENTIALS_DIR}/${CERT_FILE} --localcerts.cabundle=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt --strict=true ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

## will fail due to self-signed certificate in strict mode, if we do not supply same as CA
./ed25519tool certverify --localcerts.signingbundle=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt --strict=true ${TESTING_OUTPUT_DIR}/acceptable-timestamp-sample-infile.txt.sig

## will succeed
./ed25519tool verify --publickeypath=${CREDENTIALS_DIR}/${PUBLIC_KEY_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/future-timestamp-sample-infile.txt.sig

## should and will fail with timestamp message
./ed25519tool certverify --localcerts.signingbundle=${CREDENTIALS_DIR}/${CERT_FILE} --localcerts.cabundle=${CREDENTIALS_DIR}/${CERT_FILE} ${TESTING_INPUT_DIR}/sample-infile.txt ${TESTING_OUTPUT_DIR}/future-timestamp-sample-infile.txt.sig

```