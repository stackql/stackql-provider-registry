package main

import (
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSignAndVerifyCLI(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKQL_SIGNING_SEED", hex.EncodeToString(key.Bytes()))
	dir := t.TempDir()
	doc := filepath.Join(dir, "provider.yaml")
	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(doc, []byte("name: example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := json.Marshal(map[string]string{"test": hex.EncodeToString(key.PublicKey().Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign-doc", "-kid", "test", doc}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify-doc", "-public-keys", keys, doc}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(doc + ".sig"); !os.IsNotExist(err) {
		t.Fatal("unexpected sidecar")
	}
	if err := run([]string{"verify-doc", doc}, io.Discard); err == nil {
		t.Fatal("ephemeral key was trusted by production verifier")
	}
	t.Setenv("STACKQL_SIGNING_SEED", "bad")
	if err := run([]string{"sign-doc", "-kid", "test", doc}, io.Discard); err == nil {
		t.Fatal("accepted invalid seed")
	}
}
