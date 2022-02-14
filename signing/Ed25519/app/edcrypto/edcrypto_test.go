package edcrypto_test

import (
	"crypto/x509/pkix"
	"fmt"
	"path"
	"testing"
	"time"

	"gotest.tools/assert"

	"github.com/stackql/stackql-provider-registry/signing/pkg/fileutil"

	. "github.com/stackql/stackql-provider-registry/signing/Ed25519/app/edcrypto"
)

func TestEdCrypToE2EPublicKeyOnly(t *testing.T) {

	testName := "TestEdCrypToE2EPublicKeyOnly"

	tmpDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/tmp")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	privKeyPath := fmt.Sprintf("%s-private-key.pem", path.Join(tmpDir, testName))
	pubKeyPath := fmt.Sprintf("%s-public-key.pem", path.Join(tmpDir, testName))
	certPath := fmt.Sprintf("%s-cert.pem", path.Join(tmpDir, testName))
	csrPath := fmt.Sprintf("%s.csr", path.Join(tmpDir, testName))
	sigFilePath := fmt.Sprintf("%s.sig", path.Join(tmpDir, testName))

	cfg := CertificateConfig{
		Hosts:  []string{"example.com"},
		Format: "pem",
		Name: pkix.Name{
			Organization: []string{"stackql.io"},
		},
		IsCa:              true,
		IsEd25519Key:      true,
		ValidFor:          time.Duration(2 * 365 * 24 * time.Hour),
		PrivateKeyOutFile: privKeyPath,
		CertOutFile:       certPath,
		CsrOutFile:        csrPath,
		PublicKeyOutFile:  pubKeyPath,
	}

	err = CreateKeys(cfg)

	assert.NilError(t, err)

	b, err := SignFile(privKeyPath, "pem", fileToSign)

	assert.NilError(t, err)

	err = WriteOutFile(b, sigFilePath, "base64")

	assert.NilError(t, err)

	vr, err := NewVerifier(NewVerifierConfig("", "", ""))
	assert.NilError(t, err)

	verified, _, err := vr.VerifyFile(pubKeyPath, "pem", fileToSign, sigFilePath, "base64")

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

}

func TestTimestampedEdCrypToE2EPublicKeyOnly(t *testing.T) {

	testName := "TestTimestampedEdCrypToE2EPublicKeyOnly"

	tmpDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/tmp")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	privKeyPath := fmt.Sprintf("%s/%s-private-key.pem", tmpDir, testName)
	pubKeyPath := fmt.Sprintf("%s/%s-public-key.pem", tmpDir, testName)
	certPath := fmt.Sprintf("%s/%s-cert.pem", tmpDir, testName)
	csrPath := fmt.Sprintf("%s/%s.csr", tmpDir, testName)
	sigFilePath := fmt.Sprintf("%s/%s.sig", tmpDir, testName)

	cfg := CertificateConfig{
		Hosts:  []string{"example.com"},
		Format: "pem",
		Name: pkix.Name{
			Organization: []string{"stackql.io"},
		},
		IsCa:              true,
		IsEd25519Key:      true,
		ValidFor:          time.Duration(2 * 365 * 24 * time.Hour),
		PrivateKeyOutFile: privKeyPath,
		CertOutFile:       certPath,
		CsrOutFile:        csrPath,
		PublicKeyOutFile:  pubKeyPath,
	}

	err = CreateKeys(cfg)

	assert.NilError(t, err)

	b, err := SignFileWithTimestamp(privKeyPath, "pem", fileToSign, "Jan 2 15:04:05 2006")

	assert.NilError(t, err)

	err = WriteOutFile(b, sigFilePath, "base64")

	assert.NilError(t, err)

	vr, err := NewVerifier(NewVerifierConfig("", "", ""))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFile(pubKeyPath, "pem", fileToSign, sigFilePath, "base64")

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Equal(t, obs.HasTimestamp(), true)

}

func TestTimestampedEdCryptoCert(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := path.Join(credsDir, "sample", "sample-ed25519-cert.pem")
	sigFilePath := path.Join(credsDir, "sample-ed25519-signed-with-timestamp.sig")

	vr, err := NewVerifier(NewVerifierConfig("", path.Join(credsDir, "sample"), ""))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64", false)

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Equal(t, obs.HasTimestamp(), true)

}

func TestTimestampedEdCryptoCertAcceptable(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := path.Join(credsDir, "sample", "sample-ed25519-cert.pem")
	sigFilePath := path.Join(credsDir, "acceptable-timestamp-sample-infile.txt.sig")

	vr, err := NewVerifier(NewVerifierConfig("", path.Join(credsDir, "sample"), ".*"))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64", false)

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Equal(t, obs.HasTimestamp(), true)

}

func TestTimestampedEdCryptoCertAcceptableButCertVerifyFail(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := path.Join(credsDir, "sample", "sample-ed25519-cert.pem")
	sigFilePath := path.Join(credsDir, "acceptable-timestamp-sample-infile.txt.sig")

	vr, err := NewVerifier(NewVerifierConfig("", path.Join(credsDir, "sample"), ""))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64", true)

	assert.Assert(t, err != nil)

	assert.Equal(t, verified, false)

	assert.Assert(t, obs == nil)

}

func TestTimestampedEdCryptoCertAcceptableAndCertVerifyFromEmbeddedSuccessful(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := path.Join(credsDir, "embedded-cert.pem")
	sigFilePath := path.Join(credsDir, "acceptable-timestamp-sample-infile.txt.embedded.sig")

	vr, err := NewVerifier(NewVerifierConfig("", "", ""))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64", true)

	assert.NilError(t, err)

	assert.Equal(t, verified, true)

	assert.Assert(t, obs != nil)

}

func TestTimestampedEdCryptoCertTooOld(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := path.Join(credsDir, "sample-ed25519-cert.pem")
	sigFilePath := path.Join(credsDir, "old-timestamp-sample-infile.txt.sig")

	vr, err := NewVerifier(NewVerifierConfig("", "", ""))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64", false)

	assert.Assert(t, err != nil)

	assert.Equal(t, verified, false)

	assert.Assert(t, obs == nil)

}

func TestTimestampedEdCryptoCertTooNew(t *testing.T) {

	credsDir, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test")

	assert.NilError(t, err)

	fileToSign, err := fileutil.GetFilePathFromRepositoryRoot("signing/Ed25519/test/sample-infile.txt")

	assert.NilError(t, err)

	certPath := path.Join(credsDir, "sample-ed25519-cert.pem")
	sigFilePath := path.Join(credsDir, "future-timestamp-sample-infile.txt.sig")

	vr, err := NewVerifier(NewVerifierConfig("", "", ""))
	assert.NilError(t, err)

	verified, obs, err := vr.VerifyFileFromCertificate(certPath, "pem", fileToSign, sigFilePath, "base64", false)

	assert.Assert(t, err != nil)

	assert.Equal(t, verified, false)

	assert.Assert(t, obs == nil)

}
