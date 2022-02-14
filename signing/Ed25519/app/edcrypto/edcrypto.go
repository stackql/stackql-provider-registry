package edcrypto

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"crypto/ed25519"
	"crypto/x509"
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
	return retrievePemBytes(b)
}

func retrievePemBytes(b []byte) ([]byte, error) {
	var err error
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Bytes == nil || len(blk.Bytes) == 0 {
		return nil, fmt.Errorf("could not decode bytes")
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

func retrieveCertBundleFromPem(b []byte) ([]*x509.Certificate, error) {
	var derBytes []byte
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Bytes == nil || len(blk.Bytes) == 0 {
		return nil, fmt.Errorf("could not decode bytes")
	}
	derBytes = append(derBytes, blk.Bytes...)
	for {
		if len(rest) == 0 {
			break
		}
		blk, rest = pem.Decode(rest)
		derBytes = append(derBytes, blk.Bytes...)
	}
	return x509.ParseCertificates(derBytes)
}

func RetrieveAndDecodeHexFile(filePath string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return retrieveAndDecodeHexBytes(b)
}

func RetrieveSignatureFromFile(filePath string, format string) ([]byte, error) {
	return retrieveSignatureFromFile(filePath, format)
}

func retrieveSignatureFromFile(filePath string, format string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return retrieveSignatureFromBytes(b, format)
}

func retrieveSignatureFromBytes(b []byte, format string) ([]byte, error) {
	switch format {
	case "base64":
		return retrieveAndDecodeBase64Bytes(b)
	case "hex":
		return retrieveAndDecodeHexBytes(b)
	default:
		return nil, fmt.Errorf("signature format '%s' not supported", format)
	}
}

func retrieveAndDecodeHexBytes(b []byte) ([]byte, error) {
	return hex.DecodeString(string(b))
}

func retrieveAndDecodeBase64Bytes(b []byte) ([]byte, error) {

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

func CreateKeys(cc CertificateConfig) error {
	if cc.Format != "pem" {
		return fmt.Errorf("key format '%s' not suported", cc.Format)
	}
	return generateTLSArtifacts(cc)
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

type Verifier struct {
	cc                CertChecker
	signingCerts      []*x509.Certificate
	localSigningCerts []*x509.Certificate
	vc                VerifierConfig
	localCertsRegex   *regexp.Regexp
}

type VerifierConfig struct {
	LocalCAFilePath   string
	LocalCertDirPath  string
	LocalCertRegexStr string
}

func NewVerifierConfig(localCafilePath, localCertDirPAth, localCertRegexStr string) VerifierConfig {
	return VerifierConfig{
		LocalCAFilePath:   localCafilePath,
		LocalCertDirPath:  localCertDirPAth,
		LocalCertRegexStr: localCertRegexStr,
	}
}

func NewVerifier(vc VerifierConfig) (*Verifier, error) {
	cc, err := getCertChecker(vc.LocalCAFilePath)
	if err != nil {
		return nil, err
	}
	var scs []*x509.Certificate
	scs, err = getAllEmbeddedCerts()
	if err != nil {
		return nil, err
	}
	var localCerts []*x509.Certificate
	var localCertsRegex *regexp.Regexp
	if vc.LocalCertDirPath != "" {
		localCerts, err = getAllLocalCerts(vc.LocalCertDirPath)
		if err != nil {
			return nil, err
		}
		localCertsRegex, err = regexp.Compile(vc.LocalCertRegexStr)
		if err != nil {
			return nil, err
		}
	}
	return &Verifier{cc: cc, signingCerts: scs, localSigningCerts: localCerts, localCertsRegex: localCertsRegex, vc: vc}, nil
}

func (v *Verifier) VerifyFile(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string) (bool, *ObjectSignature, error) {
	return v.verifyFile(publicKeyFilePath, publicKeyFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, nil, nil)
}

func (v *Verifier) VerifyFileWithTimestamp(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string) (bool, *ObjectSignature, error) {
	return v.verifyFile(publicKeyFilePath, publicKeyFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, nil, nil)
}

func (v *Verifier) inferCertificate(artifactURL string, signature *ObjectSignature) (*x509.Certificate, error) {
	if signature.tmstp == nil {
		return nil, fmt.Errorf("timestamp missing from signature; cannot infer matching certificate")
	}
	if v.vc.LocalCertDirPath != "" && v.localCertsRegex != nil && v.localCertsRegex.MatchString(artifactURL) {
		return findFirstMatchingCert(v.localSigningCerts, *signature.tmstp)
	}
	return findFirstMatchingCert(v.signingCerts, *signature.tmstp)
}

func findFirstMatchingCert(cs []*x509.Certificate, t time.Time) (*x509.Certificate, error) {
	for _, c := range cs {
		if (c.NotBefore.Before(t) || c.NotBefore.Equal(t)) && (c.NotAfter.After(t) || c.NotAfter.Equal(t)) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("cannot find cert covering time = %s", t.String())
}

func (v *Verifier) verifyFile(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string, minTime *time.Time, maxTime *time.Time) (bool, *ObjectSignature, error) {
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

func (v *Verifier) VerifyFileFromCertificate(filePathToVerify string, signatureFilePath string, signatureFileFormat string, strictMode bool) (bool, *ObjectSignature, error) {
	return v.verifyFileFromCertificate(filePathToVerify, signatureFilePath, signatureFileFormat, strictMode)
}

type VerifyContext struct {
	VerifyURL                 string
	SignatureFile, VerifyFile io.ReadCloser
	CertificateFormat         string
	SignatureEncoding         string
	StrictMode                bool
	VerifyOptions             x509.VerifyOptions
}

func NewVerifyContext(verifyURL string, signatureFile, verifyFile io.ReadCloser, sigEncoding string, strictMode bool, verifyOptions x509.VerifyOptions) VerifyContext {
	return VerifyContext{
		VerifyURL:         verifyURL,
		SignatureFile:     signatureFile,
		VerifyFile:        verifyFile,
		SignatureEncoding: sigEncoding,
		StrictMode:        strictMode,
		VerifyOptions:     verifyOptions,
	}
}

func (v *Verifier) verifyFileFromCertificate(filePathToVerify string, signatureFilePath string, signatureFileFormat string, strictMode bool) (bool, *ObjectSignature, error) {
	sb, err := os.Open(signatureFilePath)
	if err != nil {
		return false, nil, err
	}
	vb, err := os.Open(filePathToVerify)
	if err != nil {
		return false, nil, err
	}
	vc := NewVerifyContext(fmt.Sprintf("file://%s", filePathToVerify), sb, vb, signatureFileFormat, strictMode, x509.VerifyOptions{})
	return v.verifyFileFromCertificateBytes(vc)
}

func (v *Verifier) VerifyFileFromCertificateBytes(vc VerifyContext) (bool, *ObjectSignature, error) {
	return v.verifyFileFromCertificateBytes(vc)
}

// Might eventually do this in chunks, io.ReadCloser is appropriate interface to pass through
func (v *Verifier) verifyFileFromCertificateBytes(vc VerifyContext) (bool, *ObjectSignature, error) {
	var publicKeyBytes ed25519.PublicKey
	var cert *x509.Certificate
	var err error
	var decodedSigBytes []byte
	cleanup := func() {
		vc.SignatureFile.Close()
		vc.VerifyFile.Close()
	}
	defer cleanup()
	sb, err := io.ReadAll(vc.SignatureFile)
	if err != nil {
		return false, nil, err
	}
	vb, err := io.ReadAll(vc.VerifyFile)
	if err != nil {
		return false, nil, err
	}
	decodedSigBytes, err = retrieveSignatureFromBytes(sb, vc.SignatureEncoding)
	if err != nil {
		return false, nil, err
	}
	obSig, err := extractSignature(decodedSigBytes)
	if err != nil {
		return false, nil, fmt.Errorf("error with signature: %s", err.Error())
	}
	cert, err = v.inferCertificate(vc.VerifyURL, obSig)
	if err != nil {
		return false, nil, err
	}
	if vc.StrictMode {
		chains, err := v.cc.Verify(cert)
		if err != nil {
			return false, nil, fmt.Errorf("certificate verify error: %s", err.Error())
		}
		if len(chains) == 0 {
			return false, nil, fmt.Errorf("chain of trust could not be established")
		}
	}
	publicKeyBytes, err = extractPublicKeyFromCertificate(cert)
	if err != nil {
		return false, nil, err
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false, nil, fmt.Errorf("public key is not the correct size (%d != %d)", len(publicKeyBytes), ed25519.PublicKeySize)
	}
	if !obSig.HasTimestamp() || !cert.NotBefore.Before(*obSig.GetTimestamp()) || !cert.NotAfter.After(*obSig.GetTimestamp()) {
		return false, nil, fmt.Errorf("error with signed timestamp: %v, not in cert timestamp range (%v, %v)", obSig.GetTimestamp(), cert.NotBefore, cert.NotAfter)
	}
	return ed25519.Verify(publicKeyBytes, append(vb, obSig.GetTimestampBytes()...), obSig.GetSignature()), obSig, nil
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
