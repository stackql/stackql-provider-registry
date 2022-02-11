
# StackQL Provider Registry

A repository of `provider` interface documents supporting [stackql](https://stackql.io/) ([github](https://github.com/stackql/stackql)). 

## Current Providers

- Google.
- Okta.

## Signing and verification

See [docs/signing-and-verification.md](/docs/signing-and-verification.md).

To build the signing and verification tool:

```
go build -o ed25519tool ./signing/Ed25519/app/cmd/main
```

Then:

```
./ed25519tool createkeys ${HOME}/stackql/stackql-provider-registry/signing/Ed25519/setup/ed25519-golib-private-key.pem ${HOME}/stackql/stackql-provider-registry/signing/Ed25519/setup/ed25519-golib-public-key.pem

./ed25519tool sign --privatekeypath=${HOME}/stackql/stackql-provider-registry/signing/Ed25519/setup/ed25519-golib-private-key.pem ${HOME}/stackql/stackql-provider-registry/signing/Ed25519/test/sample-infile.txt -o ${HOME}/stackql/stackql-provider-registry/signing/Ed25519/test/sample-infile.txt.sig

./ed25519tool verify --publickeypath=${HOME}/stackql/stackql-provider-registry/signing/Ed25519/setup/ed25519-golib-public-key.pem ${HOME}/stackql/stackql-provider-registry/signing/Ed25519/test/sample-infile.txt ${HOME}/stackql/stackql-provider-registry/signing/Ed25519/test/sample-infile.txt.sig

```
