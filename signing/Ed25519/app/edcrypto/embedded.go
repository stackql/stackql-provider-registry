package edcrypto

import (
	"crypto/x509"
	"embed"
	"fmt"
)

const (
	bundlePath string = "embeddedcerts/stackql-cert-bundle.pem"
)

//go:embed embeddedcerts/*
var certProvider embed.FS

func getEmbbededCertBundle() ([]byte, error) {
	return certProvider.ReadFile(bundlePath)
}

func getEmbbededCert(certPath string) (*x509.Certificate, error) {
	b, err := certProvider.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(b)
}

func getAllEmbeddedCertPaths() ([]string, error) {
	var rv []string
	paths, err := certProvider.ReadDir("embeddedcerts")
	if err != nil {
		return nil, err
	}
	for _, s := range paths {
		if s.Type().IsRegular() {
			rv = append(rv, fmt.Sprintf("embeddedcerts/%s", s.Name()))
		}
	}
	return rv, nil
}

func getAllEmbeddedCerts() ([]*x509.Certificate, error) {
	var rv []*x509.Certificate
	paths, err := getAllEmbeddedCertPaths()
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		c, err := getEmbbededCert(p)
		if err != nil {
			return nil, err
		}
		rv = append(rv, c)
	}
	return rv, nil
}
