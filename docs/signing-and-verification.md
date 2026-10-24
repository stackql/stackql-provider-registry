# Quantum-safe provider document signatures

Provider documents use **ML-DSA-65**, the post-quantum signature scheme specified
by FIPS 204, implemented by Go 1.27's standard-library `crypto/mldsa`.
This is algorithm compliance, not a claim that the deployment is FIPS 140 validated.
There is no Ed25519, X.509, signed timestamp, certificate-renewal tool, or `.sig`
sidecar fallback.

Every `provider.yaml` and service document carries:

```yaml
x-stackql-signature:
  format: raw-v1
  alg: ML-DSA-65
  kid: stackql-2026-01
  sig: <6618 hexadecimal characters>
  end: stackql-provider-signature
```

[`signing/pqsig`](../signing/pqsig) owns the wire format, payload framing,
signing, verification and embedded public keys. Both SDKs use this package;
they must not implement separate framing logic.
It is published as the small, nested Go module
`github.com/stackql/stackql-provider-registry/signing`, with tags named
`signing/vX.Y.Z`. Provider YAML data is not shipped in this module: the full
registry exceeds Go's module-zip size limit.

The initial prerelease is `signing/v0.1.0-alpha01` (module version
`v0.1.0-alpha01`). Squash the library feature branch before tagging its final
commit, then merge it with a merge commit, not squash or rebase, so the tagged
commit remains in `main` history. SDK releases follow the same rule. Consumers
pin named module versions and run `go mod tidy` before CI; published tags must
never be moved. StackQL itself can be squash-merged as usual.

1. The payload is the exact original block-style YAML mapping, including its
   original whitespace, comments and line endings.
2. Append a separating LF and the exact field shown above, with two-space
   indentation, the prescribed field order, and a final LF.
3. Sign or verify the payload bytes (excluding the separating LF and frame)
   with ML-DSA context `stackql-provider-doc-bytes-v1`.
4. On success, parse the returned **exact authenticated payload**, not the
   envelope-bearing document.

Only the prescribed terminal frame is accepted. Extra fields, trailing content,
duplicate frames, malformed signatures and unknown formats fail closed.
Multiple YAML documents, flow-style/JSON roots and explicit `...` document-end
markers cannot carry this frame and are rejected. An existing raw-v1 frame can
be replaced when re-signing. Editing or reformatting a signed file invalidates it.

This intentionally supersedes the issues' RFC 8785 proposal: an audit found
hundreds of existing documents with aliases and large numeric values that
canonical JSON could not preserve exactly. Raw payload signatures preserve
those existing specifications without rounding numbers or rewriting YAML.
Public trust stores map key IDs to hex-encoded ML-DSA-65 public keys.
Unknown IDs, algorithms, malformed envelopes, missing signatures and tampering
fail closed when verification is enabled.

## CI and key management

The production seed is held only in the registry's `MLDSA_SIGNING_SEED` Actions
secret; the public key is in [`keys.json`](../signing/pqsig/keys.json).
The packaging script signs into the staged tree, never the source tree.
PR builds use ephemeral seeds, never the production secret. Trusted publication
jobs additionally verify against the embedded public keys before packaging.
The standalone signature checks run even when no provider source changed.

See [CLI usage and rotation](command-line-tool.md). Keep old public keys while
their signed archives remain supported. There is no certificate expiry or
automatic trust-on-first-use.

## Runtime compatibility and scope

StackQL's default `verifyConfig.nopVerify: true` is unchanged. Explicit
`nopVerify: false` requires an embedded ML-DSA signature on every document read.
Existing unsigned providers and old sidecar-only archives remain usable with
verification disabled; enabling verification requires republishing/re-signing
them. Legacy certificate configuration and sidecars are no longer used.
An explicit `publicKeys` map replaces the embedded roots for private registries.

any-sdk verifies local, cached and remote reads. omnisdk offers
`stackqldoc.WithVerifier` and `Args.DocumentVerifier`, including referenced
operation documents. Verified omnisdk reads bypass the shared parsed-document
cache so an unverified or differently trusted cache entry cannot be reused.

This change does **not** authenticate archive downloads or extraction, the
provider index, freshness, or provider/version placement. It does not prevent
rollback to an older valid signed document. Those are separate trust-policy
and verify-before-extraction work under stackql/stackql#832.

The originally proposed dual-sign/fallback transition is intentionally omitted:
verification has been opt-in for years, and the coordinated migration removes
the legacy implementation rather than maintaining two trust mechanisms.
