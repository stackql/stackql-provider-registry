package edcrypto

import (
	"bytes"
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

	log "github.com/sirupsen/logrus"
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
		return nil, fmt.Errorf("ERROR could not decode bytes (retrievePemBytes)")
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
		return nil, fmt.Errorf("ERROR key type '%T' not supported yet", key)
	}
}

func retrieveCertBundleFromPem(b []byte) ([]*x509.Certificate, error) {
	var derBytes []byte
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Bytes == nil || len(blk.Bytes) == 0 {
		return nil, fmt.Errorf("ERROR could not decode bytes (retrieveCertBundleFromPem)")
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
		return nil, fmt.Errorf("ERROR signature format '%s' not supported", format)
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
		return fmt.Errorf("ERROR key format '%s' not suported", cc.Format)
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
	return signFileUsingPkFile(pkFilePath, pkFileFormat, filePathToSign, "")
}

func SignFileWithTimestamp(pkFilePath string, pkFileFormat string, filePathToSign string, tmstp string) ([]byte, error) {
	return signFileUsingPkFile(pkFilePath, pkFileFormat, filePathToSign, tmstp)
}

func SignFileAndWriteSignatureFile(pkFilePath string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	return signFileAndWriteSignatureFileUsingFile(pkFilePath, pkFileFormat, filePathToSign, signatureFilePath)
}

func SignFileUsingEnvVar(pkEnvVar string, pkFileFormat string, filePathToSign string) ([]byte, error) {
	return signFileUsingPkEnvVar(pkEnvVar, pkFileFormat, filePathToSign, "")
}

func SignFileWithTimestampUsingEnvVar(pkEnvVar string, pkFileFormat string, filePathToSign string, tmstp string) ([]byte, error) {
	return signFileUsingPkEnvVar(pkEnvVar, pkFileFormat, filePathToSign, tmstp)
}

func SignFileAndWriteSignatureFileUsingEnvVar(pkEnvVar string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	return signFileAndWriteSignatureFileUsingEnvVar(pkEnvVar, pkFileFormat, filePathToSign, signatureFilePath)
}

func signFileAndWriteSignatureFileUsingFile(pkFile string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	b, err := signFileUsingPkFile(pkFile, pkFileFormat, filePathToSign, "")
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(signatureFilePath, b, 0666)
	return b, err
}

func signFileAndWriteSignatureFileUsingEnvVar(pkEnvVar string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	b, err := signFileUsingPkEnvVar(pkEnvVar, pkFileFormat, filePathToSign, "")
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(signatureFilePath, b, 0666)
	return b, err
}

func signFileUsingPkEnvVar(pkEnvVar string, pkFileFormat string, filePathToSign string, timestampToInclude string) ([]byte, error) {
	var pkBytes ed25519.PrivateKey
	var err error
	fmt.Printf("using private key env var: %s", pkEnvVar)
	pk, ok := os.LookupEnv(pkEnvVar)
	if !ok {
		return nil, fmt.Errorf("ERROR env var '%s' not present as required", pkEnvVar)
	}
	switch pkFileFormat {
	case "pem":
		pkBytes, err = retrievePemBytes([]byte(pk))
	}
	if err != nil {
		return nil, err
	}
	return signFile(pkBytes, pkFileFormat, filePathToSign, timestampToInclude)
}

func signFileUsingPkFile(pkFilePath string, pkFileFormat string, filePathToSign string, timestampToInclude string) ([]byte, error) {
	var pkBytes ed25519.PrivateKey
	var err error
	pk, err := os.ReadFile(pkFilePath)
	if err != nil {
		return nil, err
	}
	switch pkFileFormat {
	case "pem":
		pkBytes, err = retrievePemBytes([]byte(pk))
	}
	if err != nil {
		return nil, err
	}
	return signFile(pkBytes, pkFileFormat, filePathToSign, timestampToInclude)
}

func signFile(pkBytes []byte, pkFileFormat string, filePathToSign string, timestampToInclude string) ([]byte, error) {
	var err error
	if len(pkBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ERROR private key is not the correct size (%d != %d)", len(pkBytes), ed25519.PrivateKeySize)
	}
	msg, err := os.ReadFile(filePathToSign)
	if err != nil {
		return nil, fmt.Errorf("ERROR cant read file to sign: %s", err.Error())
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

func NewVerifierConfig(localCafilePath, localSigningCertPath, localCertRegexStr string) VerifierConfig {
	return VerifierConfig{
		LocalCAFilePath:      localCafilePath,
		LocalSigningCertPath: localSigningCertPath,
		LocalCertRegexStr:    localCertRegexStr,
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
	if vc.LocalSigningCertPath != "" {
		localCerts, err = getAllLocalCerts(vc.LocalSigningCertPath)
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

func (v *Verifier) inferCertificate(vc VerifyContext, vb []byte, signature *ObjectSignature) (bool, *x509.Certificate, error) {
	if signature.tmstp == nil {
		return false, nil, fmt.Errorf("ERROR timestamp missing from signature; cannot infer matching certificate")
	}
	if v.vc.LocalSigningCertPath != "" && v.localCertsRegex != nil && v.localCertsRegex.MatchString(vc.VerifyURL) {
		return v.findFirstMatchingCert(vc, vb, v.localSigningCerts, signature)
	}
	return v.findFirstMatchingCert(vc, vb, v.signingCerts, signature)
}

func (v *Verifier) findFirstMatchingCert(vc VerifyContext, vb []byte, cs []*x509.Certificate, signature *ObjectSignature) (bool, *x509.Certificate, error) {
	for _, cert := range cs {
		if vc.StrictMode {
			chains, err := v.cc.Verify(cert)
			if err != nil {
				return false, nil, fmt.Errorf("ERROR certificate verify error: %s", err.Error())
			}
			if len(chains) == 0 {
				return false, nil, fmt.Errorf("ERROR chain of trust could not be established")
			}
		}
		publicKeyBytes, err := extractPublicKeyFromCertificate(cert)
		if err != nil {
			return false, nil, err
		}
		if len(publicKeyBytes) != ed25519.PublicKeySize {
			return false, nil, fmt.Errorf("ERROR public key is not the correct size (%d != %d)", len(publicKeyBytes), ed25519.PublicKeySize)
		}
		if !signature.HasTimestamp() || !cert.NotBefore.Before(*signature.GetTimestamp()) || !cert.NotAfter.After(*signature.GetTimestamp()) {
			return false, nil, fmt.Errorf("ERROR problems with signed timestamp: %v, not in cert timestamp range (%v, %v)", signature.GetTimestamp(), cert.NotBefore, cert.NotAfter)
		}
		testSubstrate := append(vb, signature.GetTimestampBytes()...)
		sigBytesCheck := signature.GetSignature()
		log.Debugf("\nhex encoded vb: %s\n\n", hex.EncodeToString(vb))
		log.Debugf("calling verify with len(vb) = %d, len(testSubstrate) = %d and len(sigBytesCheck) = %d\n", len(vb), len(testSubstrate), len(sigBytesCheck))
		isVerified := ed25519.Verify(publicKeyBytes, testSubstrate, sigBytesCheck)
		if isVerified {
			rv := cert
			return true, rv, nil
		}
	}
	return false, nil, fmt.Errorf("ERROR cannot locate appropriate certificate")
}

func findFirstMatchingCert(cs []*x509.Certificate, t time.Time) (*x509.Certificate, error) {
	for _, c := range cs {
		if (c.NotBefore.Before(t) || c.NotBefore.Equal(t)) && (c.NotAfter.After(t) || c.NotAfter.Equal(t)) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("ERROR cannot find cert covering time = %s", t.String())
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
		return false, nil, fmt.Errorf("ERROR private key '%s' is not the correct size (%d != %d)", publicKeyFilePath, len(publicKeyBytes), ed25519.PublicKeySize)
	}
	msg, err := os.ReadFile(filePathToVerify)
	if err != nil {
		return false, nil, fmt.Errorf("ERROR cant read file to sign: %s", err.Error())
	}
	b, err := retrieveSignatureFromFile(signatureFilePath, signatureFileFormat)
	if err != nil {
		return false, nil, fmt.Errorf("ERROR cant read signature file: %s", err.Error())
	}
	obSig, err := extractSignature(b)
	if err != nil {
		return false, nil, fmt.Errorf("ERROR problems with signature: %s", err.Error())
	}
	return ed25519.Verify(publicKeyBytes, append(msg, obSig.GetTimestampBytes()...), obSig.GetSignature()), obSig, nil
}

func extractPublicKeyFromCertificate(cert *x509.Certificate) (ed25519.PublicKey, error) {
	rv, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ERROR cannot extract public key from certificate")
	}
	return rv, nil
}

func (v *Verifier) VerifyFileFromCertificate(filePathToVerify string, signatureFilePath string, signatureFileFormat string, strictMode bool) (VerifierResponse, error) {
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

func (v *Verifier) verifyFileFromCertificate(filePathToVerify string, signatureFilePath string, signatureFileFormat string, strictMode bool) (VerifierResponse, error) {
	sb, err := os.Open(signatureFilePath)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), err
	}
	vb, err := os.Open(filePathToVerify)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), err
	}
	vc := NewVerifyContext(fmt.Sprintf("file://%s", filePathToVerify), sb, vb, signatureFileFormat, strictMode, x509.VerifyOptions{})
	return v.verifyFileFromCertificateBytes(vc)
}

func (v *Verifier) VerifyFileFromCertificateBytes(vc VerifyContext) (VerifierResponse, error) {
	return v.verifyFileFromCertificateBytes(vc)
}

type VerifierResponse struct {
	IsVerified    bool
	Sig           *ObjectSignature
	VerifyFile    io.ReadCloser
	SignatureFile io.ReadCloser
}

func NewVerifierResponse(isVerified bool, sig *ObjectSignature, verifyFile, sigFile io.ReadCloser) VerifierResponse {
	return VerifierResponse{
		IsVerified:    isVerified,
		Sig:           sig,
		VerifyFile:    verifyFile,
		SignatureFile: sigFile,
	}
}

// Might eventually do this in chunks, io.ReadCloser is appropriate interface to pass through
func (v *Verifier) verifyFileFromCertificateBytes(vc VerifyContext) (VerifierResponse, error) {
	if v.vc.IsNopVerify() {
		return NewVerifierResponse(true, nil, vc.VerifyFile, vc.SignatureFile), nil
	}
	var err error
	var decodedSigBytes []byte
	cleanup := func() {
		vc.SignatureFile.Close()
		vc.VerifyFile.Close()
	}
	defer cleanup()
	sb, err := io.ReadAll(vc.SignatureFile)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), err
	}
	sbc := make([]byte, len(sb))
	copy(sbc, sb)
	sigReader := io.NopCloser(bytes.NewReader(sbc))
	vb, err := io.ReadAll(vc.VerifyFile)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), err
	}
	log.Debugf("at birth; len(vb) = %d\n", len(vb))
	vbc := make([]byte, len(vb))
	copy(vbc, vb)
	log.Debugf("after copy; len(vb) = %d\n", len(vb))
	verReader := io.NopCloser(bytes.NewReader(vbc))
	decodedSigBytes, err = retrieveSignatureFromBytes(sb, vc.SignatureEncoding)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), err
	}
	obSig, err := extractSignature(decodedSigBytes)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), fmt.Errorf("ERROR problems with signature: %s", err.Error())
	}
	isVerified, _, err := v.inferCertificate(vc, vb, obSig)
	if err != nil {
		return NewVerifierResponse(false, nil, nil, nil), err
	}
	return NewVerifierResponse(isVerified, obSig, verReader, sigReader), nil
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
	return nil, fmt.Errorf("ERROR cannot process signature of size = %d", len(b))
}
