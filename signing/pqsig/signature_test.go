package pqsig_test

import (
	"bytes"
	"crypto/mldsa"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackql/stackql-provider-registry/signing/pqsig"
	"gopkg.in/yaml.v3"
)

func fixture(t *testing.T) (*mldsa.PrivateKey, pqsig.Verifier) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	v, err := pqsig.NewVerifier(map[string]string{"test": hex.EncodeToString(key.PublicKey().Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	return key, v
}

func TestSignVerifyPreservesExactPayload(t *testing.T) {
	key, v := fixture(t)
	for _, source := range []string{
		"name: example\n",
		"name: example",
		"name: example\r\n",
		"---\nname: example\n",
		"name: example\nlarge: 18446744073709551615\ndate: 2026-10-23\n",
		"original: &value {name: example}\ncopy: *value\nmerged: {<<: *value}\n",
	} {
		signed, err := pqsig.Sign([]byte(source), "test", key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := v.Verify(signed)
		if err != nil || string(got) != source {
			t.Fatalf("payload changed: got %q, %v; want %q", got, err, source)
		}
		var object map[string]any
		if err := yaml.Unmarshal(signed, &object); err != nil {
			t.Fatalf("signed output is not valid YAML: %v", err)
		}
		envelope := object[pqsig.SignatureField].(map[string]any)
		if len(envelope["sig"].(string)) != 2*mldsa.MLDSA65SignatureSize {
			t.Fatal("signature is not hex-encoded ML-DSA-65")
		}
		resigned, err := pqsig.Sign(signed, "test", key)
		if err != nil {
			t.Fatal(err)
		}
		got, err = v.Verify(resigned)
		if err != nil || string(got) != source {
			t.Fatalf("re-signing changed payload: %v", err)
		}
	}
}

func TestVerificationFailsClosed(t *testing.T) {
	key, v := fixture(t)
	source := []byte("name: original\n")
	signed, err := pqsig.Sign(source, "test", key)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"tampered":            bytes.Replace(signed, []byte("original"), []byte("modified"), 1),
		"unknown key":         bytes.Replace(signed, []byte("kid: test"), []byte("kid: unknown"), 1),
		"algorithm":           bytes.Replace(signed, []byte("ML-DSA-65"), []byte("ML-DSA-44"), 1),
		"format":              bytes.Replace(signed, []byte("raw-v1"), []byte("raw-v2"), 1),
		"missing":             source,
		"null":                []byte("name: original\nx-stackql-signature: null\n"),
		"line endings":        bytes.ReplaceAll(signed, []byte("\n"), []byte("\r\n")),
		"duplicate signature": append(append([]byte{}, signed...), signed[len(source):]...),
		"trailing content":    append(append([]byte{}, signed...), []byte("name: other\n")...),
		"extra document":      append(append([]byte{}, signed...), []byte("---\nname: other\n")...),
		"truncated":           signed[:len(signed)-1],
		"payload whitespace":  append([]byte(" "), signed...),
		"invalid hex":         bytes.Replace(signed, []byte("  sig: "), []byte("  sig: zz"), 1),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if result, err := v.Verify(doc); err == nil || result != nil {
				t.Fatalf("accepted unauthenticated document: %v", err)
			}
		})
	}
	_, wrongKey := fixture(t)
	if _, err := wrongKey.Verify(signed); err == nil {
		t.Fatal("accepted wrong public key")
	}
	sig, err := key.Sign(nil, source, &mldsa.Options{Context: "stackql-provider-doc-v1"})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := yaml.Unmarshal(signed, &object); err != nil {
		t.Fatal(err)
	}
	original := object[pqsig.SignatureField].(map[string]any)["sig"].(string)
	if _, err := v.Verify(bytes.Replace(signed, []byte(original), []byte(hex.EncodeToString(sig)), 1)); err == nil {
		t.Fatal("accepted signature from another context")
	}
}

func TestRejectUnframeableDocuments(t *testing.T) {
	key, _ := fixture(t)
	for _, input := range []string{
		"", "[]", "null", `{"name":"example"}`, "a: 1\n---\nb: 2",
		"a: 1\n...\n", "a: 1\n... # end\n", "x-stackql-signature: existing\n",
		"name: example\nx-stackql-signature:\n  invalid: frame\n",
	} {
		t.Run(strings.ReplaceAll(input, "\n", " "), func(t *testing.T) {
			if _, err := pqsig.Sign([]byte(input), "test", key); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func TestTrustStore(t *testing.T) {
	if _, err := pqsig.NewVerifier(nil); err != nil {
		t.Fatalf("embedded production trust store: %v", err)
	}
	for _, keys := range []map[string]string{{}, {"": "00"}, {"test": "zz"}, {"test": "00"}} {
		if _, err := pqsig.NewVerifier(keys); err == nil {
			t.Fatal("accepted invalid trust store")
		}
	}
	key, _ := fixture(t)
	keys := map[string]string{"test": hex.EncodeToString(key.PublicKey().Bytes())}
	v, err := pqsig.NewVerifier(keys)
	if err != nil {
		t.Fatal(err)
	}
	keys["test"] = "00"
	doc, err := pqsig.Sign([]byte("name: example"), "test", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(doc); err != nil {
		t.Fatal("caller mutation changed verifier keys")
	}
}

func TestProviderCorpus(t *testing.T) {
	root := os.Getenv("PQSIG_PROVIDER_ROOT")
	if root == "" {
		t.Skip("set PQSIG_PROVIDER_ROOT to audit provider sources before a rollout")
	}
	key, v := fixture(t)
	count := 0
	err := filepath.WalkDir(root, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(file) != ".yaml" {
			return nil
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		count++
		signed, err := pqsig.Sign(data, "test", key)
		if err != nil {
			t.Errorf("%s: %v", file, err)
			return nil
		}
		got, err := v.Verify(signed)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s: payload round-trip failed: %v", file, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("no provider documents found")
	}
	t.Logf("signed and verified %d provider documents byte-for-byte", count)
}
