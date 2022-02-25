package edcrypto

type VerifierConfig struct {
	LocalCAFilePath      string `json:"CAFile" yaml:"CAFile"`
	LocalSigningCertPath string `json:"signingCertFile" yaml:"signingCertFile"`
	LocalCertRegexStr    string `json:"certRegex" yaml:"certRegex"`
	NopVerify            bool   `json:"nopVerify" yaml:"nopVerify"`
}

func (vc VerifierConfig) IsNopVerify() bool {
	return vc.NopVerify
}
