package edcrypto

import (
	"crypto/x509"
	"fmt"
)

type CertChecker interface {
	Verify(*x509.Certificate) ([][]*x509.Certificate, error)
}

func getCertChecker() (CertChecker, error) {
	return newCompositeCertChecker()
}

type CompositeCertChecker struct {
	certPool    *x509.CertPool
	isComposite bool
}

func (cc *CompositeCertChecker) Verify(ct *x509.Certificate) ([][]*x509.Certificate, error) {
	vo := x509.VerifyOptions{
		Roots: cc.certPool,
	}
	if cc.isComposite {
		return ct.Verify(vo)
	}
	chains, err := ct.Verify(vo)
	if err == nil {
		return chains, err
	}
	return ct.Verify(x509.VerifyOptions{})
}

func newCompositeCertChecker() (*CompositeCertChecker, error) {
	// if goo
	b, err := getEmbbededCertBundle()
	if err != nil {
		return nil, err
	}
	sp, err := x509.SystemCertPool()
	if err == nil && sp != nil && sp.AppendCertsFromPEM(b) {
		return &CompositeCertChecker{
			certPool:    sp,
			isComposite: true,
		}, nil
	}
	vp := x509.NewCertPool()
	if sp.AppendCertsFromPEM(b) {
		return &CompositeCertChecker{
			certPool:    vp,
			isComposite: false,
		}, nil
	}
	return nil, fmt.Errorf("cannot initialise cert pool")
}
