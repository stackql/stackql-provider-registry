package edcrypto

import (
	"fmt"
	"os"
	"time"

	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
)

func retrievePemFile(filePath string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Bytes == nil || len(blk.Bytes) == 0 {
		return nil, fmt.Errorf("could not decode bytes from pem file '%s'", filePath)
	}
	return blk.Bytes, nil
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

func CreateKeys(privateKeyFilePath, publicKeyFilePath string, format string) error {
	if format != "pem" {
		return fmt.Errorf("key format '%s' not suported", format)
	}
	pubKey, prKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	priv := createPemBytes(prKey, "PRIVATE KEY")
	pub := createPemBytes(pubKey, "PUBLIC KEY")
	err = os.WriteFile(privateKeyFilePath, priv, 0666)
	if err != nil {
		return err
	}
	err = os.WriteFile(publicKeyFilePath, pub, 0666)
	return err
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
	return signFile(pkFilePath, pkFileFormat, filePathToSign, false)
}

func SignFileWithTimestamp(pkFilePath string, pkFileFormat string, filePathToSign string) ([]byte, error) {
	return signFile(pkFilePath, pkFileFormat, filePathToSign, true)
}

func SignFileAndWriteSignatureFile(pkFilePath string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	return signFileAndWriteSignatureFile(pkFilePath, pkFileFormat, filePathToSign, signatureFilePath)
}

func signFileAndWriteSignatureFile(pkFilePath string, pkFileFormat string, filePathToSign string, signatureFilePath string) ([]byte, error) {
	b, err := signFile(pkFilePath, pkFileFormat, filePathToSign, false)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(signatureFilePath, b, 0666)
	return b, err
}

func signFile(pkFilePath string, pkFileFormat string, filePathToSign string, includeTimestamp bool) ([]byte, error) {
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
	if includeTimestamp {
		now := time.Now()
		nowBytes, err = now.MarshalBinary()
		if err != nil {
			return nil, err
		}
		msg = append(msg, nowBytes...)
	}
	return append(nowBytes, ed25519.Sign(pkBytes, msg)...), nil
}

func VerifyFile(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string) (bool, error) {
	return verifyFile(publicKeyFilePath, publicKeyFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, nil, nil)
}

func VerifyFileWithTimestamp(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string) (bool, error) {
	return verifyFile(publicKeyFilePath, publicKeyFileFormat, filePathToVerify, signatureFilePath, signatureFileFormat, nil, nil)
}

func verifyFile(publicKeyFilePath string, publicKeyFileFormat string, filePathToVerify string, signatureFilePath string, signatureFileFormat string, minTime *time.Time, maxTime *time.Time) (bool, error) {
	var publicKeyBytes ed25519.PublicKey
	var err error
	var retVal bool
	switch publicKeyFileFormat {
	case "pem":
		publicKeyBytes, err = retrievePemFile(publicKeyFilePath)
	}
	if err != nil {
		return false, err
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("private key '%s' is not the correct size (%d != %d)", publicKeyFilePath, len(publicKeyBytes), ed25519.PublicKeySize)
	}
	msg, err := os.ReadFile(filePathToVerify)
	if err != nil {
		return false, fmt.Errorf("error reding file to sign: %s", err.Error())
	}
	b, err := retrieveSignatureFromFile(signatureFilePath, signatureFileFormat)
	if err != nil {
		return false, fmt.Errorf("error reding file to sign: %s", err.Error())
	}
	if len(b) == ed25519.SignatureSize {
		sig := b
		retVal = ed25519.Verify(publicKeyBytes, msg, sig)
		return retVal, nil
	}
	if len(b) > ed25519.SignatureSize {
		tmstpBytes := b[:len(b)-ed25519.SignatureSize]
		t := time.Time{}
		err = t.UnmarshalBinary(tmstpBytes)
		if err != nil {
			return false, err
		}
		sig := b[len(b)-ed25519.SignatureSize : len(b)-1]
		retVal = ed25519.Verify(publicKeyBytes, append(msg, tmstpBytes...), sig)
		return retVal, nil
	}
	return false, fmt.Errorf("signature file of size %d not permitted", len(b))
}
