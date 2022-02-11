package edcrypto_test

import (
	"fmt"
	"testing"

	"gotest.tools/assert"

	"github.com/stackql/stackql-provider-registry/signing/pkg/fileutil"

	. "github.com/stackql/stackql-provider-registry/signing/Ed25519/app/edcrypto"
)

func TestEdCrypToE2E(t *testing.T) {

	testName := "TestEdCrypToE2E"

	tmpDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/tmp")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	privKeyPath := fmt.Sprintf("%s/%s-private-key.pem", tmpDir, testName)
	pubKeyPath := fmt.Sprintf("%s/%s-public-key.pem", tmpDir, testName)
	certPath := fmt.Sprintf("%s/%s-cert.pem", tmpDir, testName)
	sigFilePath := fmt.Sprintf("%s/%s.sig", tmpDir, testName)

	err = CreateKeys(privKeyPath, pubKeyPath, certPath, "pem")

	assert.NilError(t, err)

	b, err := SignFile(privKeyPath, "pem", fileToSign)

	assert.NilError(t, err)

	err = WriteOutFile(b, sigFilePath, "base64")

	assert.NilError(t, err)

	verified, _, err := VerifyFile(pubKeyPath, "pem", fileToSign, sigFilePath, "base64")

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

}

func TestTimestampedEdCrypToE2E(t *testing.T) {

	testName := "TestTimestampedEdCrypToE2E"

	tmpDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/tmp")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	privKeyPath := fmt.Sprintf("%s/%s-private-key.pem", tmpDir, testName)
	pubKeyPath := fmt.Sprintf("%s/%s-public-key.pem", tmpDir, testName)
	certPath := fmt.Sprintf("%s/%s-cert.pem", tmpDir, testName)
	sigFilePath := fmt.Sprintf("%s/%s.sig", tmpDir, testName)

	err = CreateKeys(privKeyPath, pubKeyPath, certPath, "pem")

	assert.NilError(t, err)

	b, err := SignFileWithTimestamp(privKeyPath, "pem", fileToSign, "Jan 2 15:04:05 2006")

	assert.NilError(t, err)

	err = WriteOutFile(b, sigFilePath, "base64")

	assert.NilError(t, err)

	verified, obs, err := VerifyFile(pubKeyPath, "pem", fileToSign, sigFilePath, "base64")

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Equal(t, obs.HasTimestamp(), true)

}

func TestTimestampedEdCryptoCert(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := fmt.Sprintf("%s/%s", credsDir, "sample-ed25519-cert.pem")
	sigFilePath := fmt.Sprintf("%s/%s", credsDir, "sample-ed25519-signed-with-timestamp.sig")

	verified, obs, err := VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64")

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Equal(t, obs.HasTimestamp(), true)

}

func TestTimestampedEdCryptoCertTooOld(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := fmt.Sprintf("%s/%s", credsDir, "sample-ed25519-cert.pem")
	sigFilePath := fmt.Sprintf("%s/%s", credsDir, "sample-ed25519-signed-with-timestamp.sig")

	verified, obs, err := VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64")

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Equal(t, obs.HasTimestamp(), true)

}
