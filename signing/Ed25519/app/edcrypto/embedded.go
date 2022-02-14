package edcrypto

import (
	"crypto/x509"
	"embed"
	"fmt"
)

const (
	rootBundlePath string = "embeddedcerts/stackql-root-cert-bundle.pem"
)

//go:embed embeddedcerts/* embeddedcerts/signingcerts/*
var certProvider embed.FS

func getEmbbededCertBundle() ([]byte, error) {
	return certProvider.ReadFile(rootBundlePath)
}

func getEmbbededCert(certPath string) ([]*x509.Certificate, error) {
	b, err := certProvider.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return retrieveCertBundleFromPem(b)
}

func getAllEmbeddedSigningCertPaths() ([]string, error) {
	var rv []string
	paths, err := certProvider.ReadDir("embeddedcerts/signingcerts")
	if err != nil {
		return nil, err
	}
	for _, s := range paths {
		if s.Type().IsRegular() {
			rv = append(rv, fmt.Sprintf("embeddedcerts/signingcerts/%s", s.Name()))
		}
	}
	return rv, nil
}

func getAllEmbeddedCerts() ([]*x509.Certificate, error) {
	var rv []*x509.Certificate
	paths, err := getAllEmbeddedSigningCertPaths()
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		c, err := getEmbbededCert(p)
		if err != nil {
			return nil, err
		}
		rv = append(rv, c...)
	}
	return rv, nil
}
