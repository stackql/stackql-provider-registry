
# Cryptographic Signing of Provider Repository Artifacts 

## Preamble

### Industry norms

We draw the analogy that signing of documents in our repository is similar in nature to signing software archives in a software distribution repository.  At this stage of our development especially there are differences in scale, volume and frequency of update.  We are thinking for the future.

As of early 2022, [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) is still the pre-eminent signing mechanism for software repositories, eg:

- [maven / gradle](https://central.sonatype.org/publish/requirements/#sign-files-with-gpgpgp)
- [debian](https://www.debian.org/doc/manuals/securing-debian-manual/deb-pack-sign.en.html) 

### The trouble with PGP

There is some furore over the continued utility of PGP:

- High profile published exploits in [GnuPG](https://bugs.chromium.org/p/project-zero/issues/detail?id=2145) and [PGP for email encryption](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-poddebniak.pdf).
- `golang` has effectively [dropped standard lib support for PGP](https://golang.org/issue/44226).

[^1] aggregates a bunch of concerns.  And [^2] is in a similar vein.

We do not make any judgement on the future of PGP, beyond assessing it as unsuitable for a repository beginning life today.

[^1]: https://latacora.micro.blog/2019/07/16/the-pgp-problem.html
[^2]: https://blog.gtank.cc/modern-alternatives-to-pgp/

### Alternatives

In light of [^1] and [^2], some indicated options for software signing instead of PGP:

- [TUF](https://theupdateframework.io/).  This does not come with an obvious public key distribution pattern and [the provided reference implementation](https://github.com/theupdateframework/python-tuf) contain a bunch of public keys baked in.  We prefer to avoid this method of key distribution, favouring something that is either fully automated or leverages existing chain of trust infrastructure.
- [signify](https://www.openbsd.org/papers/bsdcan-signify.html) / [minisign](https://jedisct1.github.io/minisign/).  Both use the `Ed25519` algorithm.  Former is used for BSD distro signing.  Key distribution is not automated.


### Ed25519

The "Edwards-Curve Digital Signature Algorithm (EdDSA)" including `Ed25519` and `Ed448` variants are described in [RFC3082](https://datatracker.ietf.org/doc/html/rfc8032).


Some more context and sample code can be drawn from:

- https://www.scottbrady91.com/openssl/creating-elliptical-curve-keys-using-openssl
- https://www.openssl.org/docs/man1.1.1/man7/Ed25519.html
- https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html


### Corollary

1. Given the controversy around PGP, we will avoid that.
2. We will use the indicated `Ed25519` signing algorithm.
3. We will couple (2) with a code signing pattern inclusive of chain of trust, similar in nature to [this](https://www.digicert.com/signing/code-signing-certificates#Code-Signing).

### Practicalities

It is possible retrospectively regenerate certificates manually (requires `faketime`):

```bash

signing/Ed25519/setup/re-generate-faketime.sh

```

Easiest thing is edit this script to reflect desired window start datetime.  Of course, you will need to possess key material and ensure it is in expected location per script.

Then, simply copy the output from `signing/Ed25519/setup/out/stackql-cert.pem` to both:

- `signing/Ed25519/app/edcrypto/embeddedcerts/signingcerts/stackql-signing-bundle.pem`.
- `signing/Ed25519/app/edcrypto/embeddedcerts/stackql-root-cert-bundle.pem`.

Following this, need to propogate a new version of this module through the toolchain.
