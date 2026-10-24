// Package pqsig signs and verifies provider documents using FIPS 204 ML-DSA-65.
package pqsig

import (
	"bytes"
	"crypto/mldsa"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	Algorithm      = "ML-DSA-65"
	Context        = "stackql-provider-doc-bytes-v1"
	SignatureField = "x-stackql-signature"
)

// VerifierConfig is the registry's opt-in verification configuration. A nil
// PublicKeys uses the embedded trust roots; an explicit keyset replaces them.
type VerifierConfig struct {
	NopVerify  bool              `json:"nopVerify" yaml:"nopVerify"`
	PublicKeys map[string]string `json:"publicKeys,omitempty" yaml:"publicKeys,omitempty"`
}

// Verifier authenticates a document and returns the exact signed payload bytes.
// Callers must parse these returned bytes, not the envelope-bearing document.
type Verifier interface {
	Verify(doc []byte) ([]byte, error)
}

type verifier struct {
	keys map[string]*mldsa.PublicKey
}

//go:embed keys.json
var embeddedKeys []byte

// NewVerifier copies and validates a kid -> hex public key trust store.
// nil selects the embedded production keys. An empty trust store is an error.
func NewVerifier(keys map[string]string) (Verifier, error) {
	if keys == nil {
		if err := json.Unmarshal(embeddedKeys, &keys); err != nil {
			return nil, fmt.Errorf("pqsig: decode embedded keys: %w", err)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("pqsig: no trusted public keys")
	}
	v := &verifier{keys: make(map[string]*mldsa.PublicKey, len(keys))}
	for kid, encoded := range keys {
		if !keyIDPattern.MatchString(kid) {
			return nil, fmt.Errorf("pqsig: invalid key ID %q", kid)
		}
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("pqsig: key %q is not hex: %w", kid, err)
		}
		key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
		if err != nil {
			return nil, fmt.Errorf("pqsig: key %q: %w", kid, err)
		}
		v.keys[kid] = key
	}
	return v, nil
}

// Sign appends a strictly framed signature field without re-encoding the payload.
// An existing raw-v1 frame is replaced. The separating newline is not payload.
func Sign(doc []byte, kid string, key *mldsa.PrivateKey) ([]byte, error) {
	if key == nil || key.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, fmt.Errorf("pqsig: an ML-DSA-65 private key is required")
	}
	if !keyIDPattern.MatchString(kid) {
		return nil, fmt.Errorf("pqsig: invalid key ID %q", kid)
	}
	if bytes.Contains(doc, []byte(signatureMarker)) {
		var err error
		doc, _, _, err = splitSignature(doc)
		if err != nil {
			return nil, err
		}
	}
	if err := Validate(doc); err != nil {
		return nil, err
	}
	signature, err := key.Sign(nil, doc, &mldsa.Options{Context: Context})
	if err != nil {
		return nil, fmt.Errorf("pqsig: sign: %w", err)
	}
	envelope := fmt.Sprintf("%s  format: raw-v1\n  alg: %s\n  kid: %s\n  sig: %s\n  end: stackql-provider-signature\n",
		signatureMarker, Algorithm, kid, hex.EncodeToString(signature))
	out := make([]byte, 0, len(doc)+len(envelope))
	out = append(out, doc...)
	out = append(out, envelope...)
	return out, nil
}

func (v *verifier) Verify(doc []byte) ([]byte, error) {
	message, kid, encoded, err := splitSignature(doc)
	if err != nil {
		return nil, err
	}
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("pqsig: unknown key ID %q", kid)
	}
	signature, err := hex.DecodeString(encoded)
	if err != nil || len(signature) != mldsa.MLDSA65SignatureSize {
		return nil, fmt.Errorf("pqsig: invalid signature encoding or length")
	}
	if err := mldsa.Verify(key, message, signature, &mldsa.Options{Context: Context}); err != nil {
		return nil, fmt.Errorf("pqsig: signature verification failed: %w", err)
	}
	if err := Validate(message); err != nil {
		return nil, err
	}
	return message, nil
}
