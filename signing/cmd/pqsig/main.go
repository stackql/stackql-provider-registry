package main

import (
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/stackql/stackql-provider-registry/signing/pqsig"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pqsig <keygen|sign-doc|verify-doc|validate-doc> [options] [files...]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	kid := flags.String("kid", "", "signing key ID")
	seedEnv := flags.String("seed-env", "STACKQL_SIGNING_SEED", "environment variable containing a hex seed")
	publicOut := flags.String("public-keys", "", "public keyset JSON file")
	secret := flags.String("github-secret", "", "store a newly generated seed in this Actions secret (never print it)")
	repo := flags.String("repo", "", "GitHub repository for key provisioning")
	output := flags.String("out", "", "output file (sign-doc defaults to in-place)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] == "keygen" {
		if *kid == "" || *publicOut == "" || *secret == "" || *repo == "" || flags.NArg() != 0 {
			return fmt.Errorf("keygen requires -kid, -public-keys, -github-secret and -repo")
		}
		if _, err := os.Stat(*publicOut); !os.IsNotExist(err) {
			return fmt.Errorf("keygen refuses to overwrite public key file %q", *publicOut)
		}
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return err
		}
		cmd := exec.Command("gh", "secret", "set", *secret, "--repo", *repo)
		cmd.Stdin = strings.NewReader(hex.EncodeToString(key.Bytes()))
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("store signing seed in GitHub Actions: %w", err)
		}
		data, err := json.MarshalIndent(map[string]string{
			*kid: hex.EncodeToString(key.PublicKey().Bytes()),
		}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*publicOut, append(data, '\n'), 0644); err != nil {
			return fmt.Errorf("write public key (seed is already provisioned): %w", err)
		}
		fmt.Fprintf(stdout, "Provisioned %s public key %s; seed stored in %s\n", pqsig.Algorithm, *kid, *secret)
		return nil
	}
	if flags.NArg() == 0 || (*output != "" && flags.NArg() != 1) {
		return fmt.Errorf("%s requires files; -out requires exactly one input file", args[0])
	}
	var signer *mldsa.PrivateKey
	var verifier pqsig.Verifier
	switch args[0] {
	case "sign-doc":
		seed, err := hex.DecodeString(os.Getenv(*seedEnv))
		if err != nil || len(seed) != mldsa.PrivateKeySize {
			return fmt.Errorf("%s must contain a hex-encoded 32-byte ML-DSA seed", *seedEnv)
		}
		signer, err = mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
		if err != nil {
			return err
		}
		verifier, err = pqsig.NewVerifier(map[string]string{*kid: hex.EncodeToString(signer.PublicKey().Bytes())})
		if err != nil {
			return err
		}
	case "verify-doc":
		var keys map[string]string
		if *publicOut != "" {
			data, err := os.ReadFile(*publicOut)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &keys); err != nil {
				return err
			}
			if keys == nil {
				return fmt.Errorf("public key file must contain a non-empty object")
			}
		}
		var err error
		verifier, err = pqsig.NewVerifier(keys)
		if err != nil {
			return err
		}
	case "validate-doc":
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	for _, file := range flags.Args() {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		switch args[0] {
		case "sign-doc":
			data, err = pqsig.Sign(data, *kid, signer)
			if err == nil {
				_, err = verifier.Verify(data)
			}
			if err == nil {
				target := file
				if *output != "" {
					target = *output
				}
				err = writeDocument(target, data)
			}
		case "verify-doc":
			_, err = verifier.Verify(data)
		case "validate-doc":
			err = pqsig.Validate(data)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		fmt.Fprintf(stdout, "%s: %s OK\n", args[0], file)
	}
	return nil
}

func writeDocument(target string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(target), ".pqsig-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), target)
}
