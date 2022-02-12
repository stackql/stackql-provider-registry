package edcrypto

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
)

const (
	privateKeyRexStr string = `PRIVATE\ KEY`
	publicKeyRexStr  string = `PUBLIC\ KEY`
)

var (
	privateKeyRegex *regexp.Regexp = regexp.MustCompile(privateKeyRexStr)
	publicKeyRegex  *regexp.Regexp = regexp.MustCompile(publicKeyRexStr)
)

func isPrivateKeyType(typeStr string) bool {
	return privateKeyRegex.MatchString(typeStr)
}

func isPublicKeyType(typeStr string) bool {
	return publicKeyRegex.MatchString(typeStr)
}

func retrievePemFile(filePath string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Bytes == nil || len(blk.Bytes) == 0 {
		return nil, fmt.Errorf("could not decode bytes from pem file '%s'", filePath)
	}
	var key interface{}
	if isPrivateKeyType(blk.Type) {
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	} else if isPublicKeyType(blk.Type) {
		key, err = x509.ParsePKIXPublicKey(blk.Bytes)
	} else {
		return blk.Bytes, nil
	}
	if err != nil {
		return nil, err
	}
	switch key := key.(type) {
	case ed25519.PrivateKey:
		return key, nil
	case ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("key type '%T' not supported yet", key)
	}
}

func RetrieveAndDecodeHexFile(filePath string) ([]byte, error) {
	return retrieveAndDecodeHexFile(filePath)
}

func RetrieveSignatureFromFile(filePath string, format string) ([]byte, error) {
	return retrieveSignatureFromFile(filePath, format)
}

func retrieveSignatureFromFile(filePath string, format string) ([]byte, error) {
	switch format {
	case "base64":
		return retrieveAndDecodeBase64File(filePath)
	case "hex":
		return retrieveAndDecodeHexFile(filePath)
	default:
		return nil, fmt.Errorf("signature format '%s' not supported", format)
	}
}

func retrieveAndDecodeHexFile(filePath string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(b))
}

func retrieveAndDecodeBase64File(filePath string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(b))
}

func WriteOutFile(outBytes []byte, filePath string, format string) error {
	return writeOutFile(outBytes, filePath, format)
}

func writeOutFile(outBytes []byte, filePath string, format string) error {
	switch format {
	case "base64":
		outBytes = []byte(base64.StdEncoding.EncodeToString(outBytes))
	case "hex":
		outBytes = []byte(hex.EncodeToString(outBytes))
	}
	err := os.WriteFile(filePath, outBytes, 0666)
	return err
}

func createPemBlock(outBytes []byte, pemType string) *pem.Block {
	return &pem.Block{
		Type:  pemType,
		Bytes: outBytes,
	}
}

func createPemBytes(objectBytes []byte, objectType string) []byte {
	pb := createPemBlock(objectBytes, objectType)
	return pem.EncodeToMemory(pb)
}

func CreateKeys(privateKeyFilePath, publicKeyFilePath, certFilePath, csrFilePath string, format string) error {
	if format != "pem" {
		return fmt.Errorf("key format '%s' not suported", format)
	}
	return generateTLSArtifacts(
		CertificateConfig{
			Host: "example.com",
			Name: pkix.Name{
				Organization: []string{"stackql.io"},
			},
			IsCa:              true,
			IseEd25519Key:     true,
			ValidFor:          time.Duration(2 * 365 * 24 * time.Hour),
			PrivateKeyOutFile: privateKeyFilePath,
			CertOutFile:       certFilePath,
			CsrOutFile:        csrFilePath,
			PublicKeyOutFile:  publicKeyFilePath,
		},
	)
}

func ReadSignatureFile(outBytes []byte, filePath string, format string) error {
	switch format {
	case "hex":
		outBytes = []byte(hex.EncodeToString(outBytes))
	}
	err := os.WriteFile(filePath, outBytes, 0666)
	return err
}

func SignFile(pkFilePath string, pkFileFormat string, filePathToSign string) ([]byte, error) {
	return signFile(pkFilePath, pkFileFormat, filePathToSign, "")
}

func SignFileWithTimestamp(pkFilePath string, pkFileFormat string, filePathToSign string, tmstp string) ([]byte, error) {
	return signFile(pkFilePath, pkFileFormat, filePathToSign, tmstp)
}

func SignFileAndWriteSignatureFile(pkFilePath string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	return signFileAndWriteSignatureFile(pkFilePath, pkFileFormat, filePathToSign, signatureFilePath)
}

func signFileAndWriteSignatureFile(pkFilePath string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	b, err := signFile(pkFilePath, pkFileFormat, filePathToSign, "")
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(signatureFilePath, b, 0666)
	return b, err
}

func signFile(pkFilePath string, pkFileFormat string, filePathToSign string, timestampToInclude string) ([]byte, error) {
	var pkBytes ed25519.PrivateKey
	var err error
	switch pkFileFormat {
	case "pem":
		pkBytes, err = retrievePemFile(pkFilePath)
	}
	if err != nil {
		return nil, err
	}
	if len(pkBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key '%s' is not the correct size (%d != %d)", pkFilePath, len(pkBytes), ed25519.PrivateKeySize)
	}
	msg, err := os.ReadFile(filePathToSign)
	if err != nil {
		return nil, fmt.Errorf("error reding file to sign: %s", err.Error())
	}
	var nowBytes []byte
	if timestampToInclude != "" {
		var tmstp time.Time
		if timestampToInclude == "now" {
			tmstp = time.Now()
		} else {
			tmstp, err = time.Parse("Jan 2 15:04:05 2006", timestampToInclude)
			if err != nil {
				return nil, err
			}
		}
		nowBytes, err = tmstp.MarshalBinary()
		if err != nil {
			return nil, err
		}
		msg = append(msg, nowBytes...)
	}
	return append(nowBytes, ed25519.Sign(pkBytes, msg)...), nil
}

func VerifyFile(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string) (bool, *ObjectSignature, error) {
	return verifyFile(publicKeyFilePath, publicKeyFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, nil, nil)
}

func VerifyFileWithTimestamp(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string) (bool, *ObjectSignature, error) {
	return verifyFile(publicKeyFilePath, publicKeyFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, nil, nil)
}

func verifyFile(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string, minTime *time.Time, maxTime *time.Time) (bool, *ObjectSignature, error) {
	var publicKeyBytes ed25519.PublicKey
	var err error
	switch publicKeyFileFormat {
	case "pem":
		publicKeyBytes, err = retrievePemFile(publicKeyFilePath)
	}
	if err != nil {
		return false, nil, err
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false, nil, fmt.Errorf("private key '%s' is not the correct size (%d != %d)", publicKeyFilePath, len(publicKeyBytes), ed25519.PublicKeySize)
	}
	msg, err := os.ReadFile(filePathToVerify)
	if err != nil {
		return false, nil, fmt.Errorf("error reading file to sign: %s", err.Error())
	}
	b, err := retrieveSignatureFromFile(signatureFilePath, signatureFileFormat)
	if err != nil {
		return false, nil, fmt.Errorf("error reading signature file: %s", err.Error())
	}
	obSig, err := extractSignature(b)
	if err != nil {
		return false, nil, fmt.Errorf("error with signature: %s", err.Error())
	}
	return ed25519.Verify(publicKeyBytes, append(msg, obSig.GetTimestampBytes()...), obSig.GetSignature()), obSig, nil
}

func extractPublicKeyFromCertificate(cert *x509.Certificate) (ed25519.PublicKey, error) {
	rv, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot extract public key from certificate")
	}
	return rv, nil
}

func VerifyFileFromCertificate(certificateFilePath string, certificateFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string, strictMode bool) (bool, *ObjectSignature, error) {
	return verifyFileFromCertificate(certificateFilePath, certificateFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, strictMode)
}

func verifyFileFromCertificate(certificateFilePath string, certificateFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string, strictMode bool) (bool, *ObjectSignature, error) {
	var publicKeyBytes ed25519.PublicKey
	var cert *x509.Certificate
	var err error
	switch certificateFileFormat {
	case "pem":
		b, err := retrievePemFile(certificateFilePath)
		if err != nil {
			return false, nil, err
		}
		cert, err = x509.ParseCertificate(b)
		if err != nil {
			return false, nil, err
		}
		if strictMode {
			_, err = cert.Verify(x509.VerifyOptions{})
			if err != nil {
				return false, nil, fmt.Errorf("ceritificate verify error: %s", err.Error())
			}
		}
		publicKeyBytes, err = extractPublicKeyFromCertificate(cert)
		if err != nil {
			return false, nil, err
		}
	default:
		return false, nil, fmt.Errorf("certificate format '%s' not supported", certificateFileFormat)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false, nil, fmt.Errorf("private key '%s' is not the correct size (%d != %d)", certificateFilePath, len(publicKeyBytes), ed25519.PublicKeySize)
	}
	msg, err := os.ReadFile(filePathToVerify)
	if err != nil {
		return false, nil, fmt.Errorf("error reading file to sign: %s", err.Error())
	}
	b, err := retrieveSignatureFromFile(signatureFilePath, signatureFileFormat)
	if err != nil {
		return false, nil, fmt.Errorf("error reading signature file: %s", err.Error())
	}
	obSig, err := extractSignature(b)
	if err != nil {
		return false, nil, fmt.Errorf("error with signature: %s", err.Error())
	}
	if !obSig.HasTimestamp() || !cert.NotBefore.Before(*obSig.GetTimestamp()) || !cert.NotAfter.After(*obSig.GetTimestamp()) {
		return false, nil, fmt.Errorf("error with signed timestamp: %v, not in cert timestamp range (%v, %v)", obSig.GetTimestamp(), cert.NotBefore, cert.NotAfter)
	}
	return ed25519.Verify(publicKeyBytes, append(msg, obSig.GetTimestampBytes()...), obSig.GetSignature()), obSig, nil
}

type ObjectSignature struct {
	tmstpBytes []byte
	sigBytes   []byte
	tmstp      *time.Time
}

func (obs *ObjectSignature) HasTimestamp() bool {
	return obs.tmstp != nil
}

func (obs *ObjectSignature) GetTimestamp() *time.Time {
	return obs.tmstp
}

func (obs *ObjectSignature) GetTimestampBytes() []byte {
	return obs.tmstpBytes
}

func (obs *ObjectSignature) GetSignature() []byte {
	return obs.sigBytes
}

func newObjectSignature(tmstpBytes, sigBytes []byte) (*ObjectSignature, error) {
	rv := &ObjectSignature{
		tmstpBytes: make([]byte, len(tmstpBytes)),
		tmstp:      nil,
		sigBytes:   make([]byte, ed25519.SignatureSize),
	}
	if len(tmstpBytes) > 0 {
		copy(rv.tmstpBytes, tmstpBytes)
		t := &time.Time{}
		err := t.UnmarshalBinary(rv.tmstpBytes)
		if err != nil {
			return nil, err
		}
		rv.tmstp = t
	}
	copy(rv.sigBytes, sigBytes)
	return rv, nil
}

func extractSignature(b []byte) (*ObjectSignature, error) {
	if len(b) > ed25519.SignatureSize {
		return newObjectSignature(
			b[:len(b)-ed25519.SignatureSize],
			b[len(b)-ed25519.SignatureSize:],
		)
	}
	if len(b) == ed25519.SignatureSize {
		return newObjectSignature(
			nil,
			b,
		)
	}
	return nil, fmt.Errorf("cannot process signature of size = %d", len(b))
}
