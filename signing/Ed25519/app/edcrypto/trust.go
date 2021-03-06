package edcrypto

import (
	"crypto/x509"
	"fmt"
)

type CertChecker interface {
	Verify(*x509.Certificate) ([][]*x509.Certificate, error)
}

func getCertChecker(localCafilePath string) (CertChecker, error) {
	return newCompositeCertChecker(localCafilePath)
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

func newCompositeCertChecker(localCafilePath string) (*CompositeCertChecker, error) {
	// if goo
	b, err := getEmbbededCertBundle()
	if err != nil {
		return nil, err
	}
	var lb []byte
	if localCafilePath != "" {
		lb, err = getLocalCertBundle(localCafilePath)
		if err != nil {
			return nil, err
		}
	}
	sp, err := x509.SystemCertPool()
	if err == nil && sp != nil && sp.AppendCertsFromPEM(b) {
		if lb != nil {
			sp.AppendCertsFromPEM(lb)
		}
		return &CompositeCertChecker{
			certPool:    sp,
			isComposite: true,
		}, nil
	}
	vp := x509.NewCertPool()
	if vp.AppendCertsFromPEM(b) {
		if lb != nil {
			vp.AppendCertsFromPEM(lb)
		}
		return &CompositeCertChecker{
			certPool:    vp,
			isComposite: false,
		}, nil
	}
	return nil, fmt.Errorf("cannot initialise cert pool where len(b) = %d and len(lb) = %d", len(b), len(lb))
}
