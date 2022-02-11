package edcrypto

import (
	"fmt"
	"os"

	"crypto/ed25519"
	"encoding/base64"
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

func SignFile(pkFilePath string, pkFileFormat string, filePathToSign string) ([]byte, error) {
	var b []byte
	var pkBytes ed25519.PrivateKey
	var err error
	switch pkFileFormat {
	case "pem":
		b, err = retrievePemFile(pkFilePath)
		pkBytes = make(ed25519.PrivateKey, base64.StdEncoding.EncodedLen(len(b)))
		base64.StdEncoding.Encode(pkBytes, b)
	}
	if err != nil {
		return nil, err
	}
	if len(pkBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key '%s' is not the correct size (%d)", pkFilePath, ed25519.PrivateKeySize)
	}
	msg, err := os.ReadFile(filePathToSign)
	if err != nil {
		return nil, fmt.Errorf("error reding file to sign: %s", err.Error())
	}
	return ed25519.Sign(pkBytes, msg), nil
}

// func GenerateKeyPair() error {
// 	privateKey, publicKey, err := ed25519.GenerateKey(nil)
// 	if err != nil {
// 		return err
// 	}
// 	privateKeyPem := &pem.Block{}

// 	return nil
// }
