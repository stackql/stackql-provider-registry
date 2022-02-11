package edcrypto

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
// host      = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
// validFrom = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
// validFor  = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
// isCA      = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
// rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
// ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
// ed25519Key = flag.Bool("ed25519", false, "Generate an Ed25519 key")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

type CertificateConfig struct {
	EcdsaCurve        string
	Host              string
	IsCa              bool
	IseEd25519Key     bool
	RsaBits           int
	ValidFor          time.Duration
	ValidFrom         string
	CertOutFile       string
	PrivateKeyOutFile string
	PublicKeyOutFile  string
}

func GenerateTLSArtifacts(cc CertificateConfig) error {
	return generateTLSArtifacts(cc)
}

func generateTLSArtifacts(cc CertificateConfig) error {

	if len(cc.Host) == 0 {
		return fmt.Errorf("missing required Host parameter")
	}

	var priv interface{}
	var err error
	switch cc.EcdsaCurve {
	case "":
		if cc.IseEd25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, cc.RsaBits)
			if err != nil {
				return err
			}
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return fmt.Errorf("Unrecognized elliptic curve: %q", cc.EcdsaCurve)
	}
	if err != nil {
		return err
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(cc.ValidFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", cc.ValidFrom)
		if err != nil {
			return err
		}
	}

	notAfter := notBefore.Add(cc.ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(cc.Host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if cc.IsCa {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	pubKey := publicKey(priv)
	pkb, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	pub := createPemBytes(pkb, "PUBLIC KEY")
	err = os.WriteFile(cc.PublicKeyOutFile, pub, 0666)
	if err != nil {
		return err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
	if err != nil {
		return err
	}
	certOut := createPemBytes(derBytes, "CERTIFICATE")
	err = os.WriteFile(cc.CertOutFile, certOut, 0666)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("Unable to marshal private key: %v", err)
	}
	privOut := createPemBytes(privBytes, "PRIVATE KEY")
	err = os.WriteFile(cc.PrivateKeyOutFile, privOut, 0600)
	if err != nil {
		return err
	}

	return nil
}
