package argparse

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackql/stackql-provider-registry/signing/Ed25519/app/edcrypto"
)

func printErrorAndExitOneIfNil(subject interface{}, msg string) {
	if subject == nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintln(msg))
		os.Exit(1)
	}
}

func printErrorAndExitOne(msg string) {
	fmt.Fprintln(os.Stderr, fmt.Sprintln(msg))
	os.Exit(1)
}

func printErrorAndExitOneIfError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintln(err.Error()))
		os.Exit(1)
	}
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Simple Ed25519 sign",
	Long:  `Simple Ed25519 sign`,
	Run: func(cmd *cobra.Command, args []string) {

		cb := func() {
			if len(args) == 0 || args[0] == "" {
				cmd.Help()
				os.Exit(1)
			}

			var b []byte
			var err error
			if runtimeCtx.PrivateKeyEnvVar != "" {
				if runtimeCtx.SignatureTime == "" {
					b, err = edcrypto.SignFileUsingEnvVar(runtimeCtx.PrivateKeyEnvVar, runtimeCtx.PrivateKeyFormat, args[0])
				} else {
					b, err = edcrypto.SignFileWithTimestampUsingEnvVar(runtimeCtx.PrivateKeyEnvVar, runtimeCtx.PrivateKeyFormat, args[0], runtimeCtx.SignatureTime)
				}
			} else {
				if runtimeCtx.SignatureTime == "" {
					b, err = edcrypto.SignFile(runtimeCtx.PrivateKeyPath, runtimeCtx.PrivateKeyFormat, args[0])
				} else {
					b, err = edcrypto.SignFileWithTimestamp(runtimeCtx.PrivateKeyPath, runtimeCtx.PrivateKeyFormat, args[0], runtimeCtx.SignatureTime)
				}
			}
			printErrorAndExitOneIfError(err)
			printErrorAndExitOneIfNil(b, "no signature created")
			// fmt.Printf("\nhex encoded signature = '%s'\n", hex.EncodeToString(b))
			fmt.Printf("\nbase64 encoded signature = '%s'\n", base64.StdEncoding.EncodeToString(b))
			if runtimeCtx.OutFilePath != "" {
				outFileFormat := runtimeCtx.OutFileFormat
				if outFileFormat == "" {
					outFileFormat = "base64"
				}
				edcrypto.WriteOutFile(b, runtimeCtx.OutFilePath, outFileFormat)
			}
		}
		executeCommand(runtimeCtx, cb)
	},
}

func getVerifierConfigFromRuntimeCfg() edcrypto.VerifierConfig {
	return edcrypto.NewVerifierConfig(runtimeCtx.LocalCABundlePath, runtimeCtx.LocalCertsPath, runtimeCtx.LocalCertsRegex)
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Simple Ed25519 verify",
	Long: `Simple Ed25519 verify
	  
	`,
	Run: func(cmd *cobra.Command, args []string) {

		cb := func() {
			if len(args) < 2 || args[0] == "" || args[1] == "" {
				cmd.Help()
				os.Exit(1)
			}

			filePathToVerify := args[0]
			signatureFilePath := args[1]
			signatureFileFormat := runtimeCtx.OutFileFormat
			if signatureFileFormat == "" {
				signatureFileFormat = "base64"
			}

			vr, err := edcrypto.NewVerifier(getVerifierConfigFromRuntimeCfg())
			printErrorAndExitOneIfError(err)

			res, _, err := vr.VerifyFile(runtimeCtx.PublicKeyPath, runtimeCtx.PublicKeyFormat, filePathToVerify, signatureFilePath, signatureFileFormat)
			printErrorAndExitOneIfError(err)
			printErrorAndExitOneIfError(err)
			if !res {
				printErrorAndExitOne(fmt.Sprintf("signature verification failed for file =  '%s' and signature file = '%s'", filePathToVerify, signatureFilePath))
			}
			fmt.Printf("\nsignature verification succeeded for file =  '%s' and signature file = '%s'\n", filePathToVerify, signatureFilePath)
		}
		executeCommand(runtimeCtx, cb)
	},
}

var certVerifyCmd = &cobra.Command{
	Use:   "certverify",
	Short: "Simple Ed25519 certverify",
	Long: `Simple Ed25519 certverify
	  
	`,
	Run: func(cmd *cobra.Command, args []string) {

		cb := func() {
			if len(args) < 2 || args[0] == "" || args[1] == "" {
				cmd.Help()
				os.Exit(1)
			}

			filePathToVerify := args[0]
			signatureFilePath := args[1]
			signatureFileFormat := runtimeCtx.OutFileFormat
			if signatureFileFormat == "" {
				signatureFileFormat = "base64"
			}

			vr, err := edcrypto.NewVerifier(getVerifierConfigFromRuntimeCfg())
			printErrorAndExitOneIfError(err)

			res, err := vr.VerifyFileFromCertificate(filePathToVerify, signatureFilePath, signatureFileFormat, runtimeCtx.Strict)
			printErrorAndExitOneIfError(err)
			printErrorAndExitOneIfError(err)
			if !res.IsVerified {
				printErrorAndExitOne(fmt.Sprintf("signature verification failed for file =  '%s' and signature file = '%s'", filePathToVerify, signatureFilePath))
			}
			fmt.Printf("\nsignature verification succeeded for file =  '%s' and signature file = '%s'\n", filePathToVerify, signatureFilePath)
		}
		executeCommand(runtimeCtx, cb)
	},
}

var createKeysCmd = &cobra.Command{
	Use:   "createkeys",
	Short: "Create Ed25519 key pair",
	Long: `Create Ed25519 key pair 
	  Usage:
		   createkeys privatekeyfilepath publickeyfilepath certfilepath
	  
	`,
	Run: func(cmd *cobra.Command, args []string) {

		cb := func() {
			if len(args) < 4 || args[0] == "" || args[1] == "" || args[2] == "" || args[3] == "" {
				cmd.Help()
				os.Exit(1)
			}

			privateKeyFilePath := args[0]
			publicKeyFilePath := args[1]
			certFilePath := args[2]
			csrFilePath := args[3]
			keyFileFormat := runtimeCtx.OutFileFormat
			if keyFileFormat == "" {
				keyFileFormat = "pem"
			}
			var org, emails []string
			if len(runtimeCtx.Organization) > 0 {
				org = strings.Split(runtimeCtx.Organization, runtimeCtx.Delimiter)
			}
			if len(runtimeCtx.EmailAddresses) > 0 {
				emails = strings.Split(runtimeCtx.EmailAddresses, runtimeCtx.Delimiter)
			}

			cfg := edcrypto.CertificateConfig{
				Hosts:  strings.Split(runtimeCtx.Host, runtimeCtx.Delimiter),
				Format: keyFileFormat,
				Name: pkix.Name{
					Organization: org,
					CommonName:   runtimeCtx.CommonName,
				},
				IsCa:              true,
				IsEd25519Key:      true,
				ValidFor:          time.Duration(2 * 365 * 24 * time.Hour),
				PrivateKeyOutFile: privateKeyFilePath,
				CertOutFile:       certFilePath,
				CsrOutFile:        csrFilePath,
				PublicKeyOutFile:  publicKeyFilePath,
				EmailAddresses:    emails,
			}

			err := edcrypto.CreateKeys(cfg)
			printErrorAndExitOneIfError(err)
		}
		executeCommand(runtimeCtx, cb)
	},
}

func RunCommand(rtCtx runtimeContext, arg string) {
	_, err := os.ReadFile(arg)
	switch arg {
	case "sign":

	}
	printErrorAndExitOneIfError(err)

}

func executeCommand(rtCtx runtimeContext, callback func()) {
	if runtimeCtx.CPUProfile != "" {
		f, err := os.Create(runtimeCtx.CPUProfile)
		if err != nil {
			printErrorAndExitOneIfError(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	callback()
}
