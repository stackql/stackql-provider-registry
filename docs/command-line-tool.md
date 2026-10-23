# Provider signing command line

Requires Go 1.27.3 or later:

```sh
cd signing
go build -o ../pqsig ./cmd/pqsig
cd ..
```

Provision a new production key without writing or displaying the private seed:

```sh
./pqsig keygen -kid stackql-2026-01 \
  -public-keys new-public-keys.json \
  -github-secret MLDSA_SIGNING_SEED \
  -repo stackql/stackql-provider-registry
```

The command generates an ML-DSA-65 key, pipes its hex-encoded 32-byte seed
directly to `gh secret set`, and writes only the public key. It refuses to
overwrite the public key file. Review and add the public entry to
[`signing/pqsig/keys.json`](../signing/pqsig/keys.json); never commit a seed.
For rotation, add rather than replace public entries until old archives expire.
Ship the updated verifier before using the new key to publish documents.

Sign in place, or write to a separate output:

```sh
# STACKQL_SIGNING_SEED is supplied by the secret manager, not a command argument.
./pqsig sign-doc -kid stackql-2026-01 provider.yaml
./pqsig sign-doc -kid stackql-2026-01 -out signed.yaml provider.yaml
./pqsig verify-doc signed.yaml
./pqsig verify-doc -public-keys custom-public-keys.json signed.yaml
./pqsig validate-doc provider.yaml
```

`sign-doc` checks the generated signature before replacing the output. It does
not assert that the key is an embedded production key; `verify-doc` does that.
CI runs both before publishing. Missing seeds, unknown keys, malformed documents
and invalid signatures exit nonzero. See [the format and policy](signing-and-verification.md).
