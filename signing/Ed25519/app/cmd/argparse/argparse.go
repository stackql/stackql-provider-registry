package argparse

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"
)

var (
	BuildMajorVersion   string = ""
	BuildMinorVersion   string = ""
	BuildPatchVersion   string = ""
	BuildCommitSHA      string = ""
	BuildShortCommitSHA string = ""
	BuildDate           string = ""
	BuildPlatform       string = ""
)

var SemVersion string = fmt.Sprintf("%s.%s.%s", BuildMajorVersion, BuildMinorVersion, BuildPatchVersion)

type runtimeContext struct {
	CPUProfile        string
	LogLevelStr       string
	PrivateKeyEnvVar  string
	PrivateKeyPath    string
	PublicKeyPath     string
	CertificatePath   string
	OutFilePath       string
	PrivateKeyFormat  string
	PublicKeyFormat   string
	Strict            bool
	CertificateFormat string
	OutFileFormat     string
	Organization      string
	Host              string
	CommonName        string
	FirstName         string
	LastName          string
	URIs              string
	EmailAddresses    string
	Delimiter         string
	SignatureTime     string
	LocalCertsPath    string
	LocalCABundlePath string
	LocalCertsRegex   string
}

var (
	runtimeCtx runtimeContext
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "ed25519",
	Version: SemVersion,
	Short:   "ed25519 sign and verify",
	Long: `
	ed25519 sign and verify
	`,
	Run: func(cmd *cobra.Command, args []string) {
		// in the root command is executed with no arguments, print the help message
		usagemsg := cmd.Long + "\n\n" + cmd.UsageString()
		fmt.Println(usagemsg)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.SetVersionTemplate("ed25519 v{{.Version}} " + BuildPlatform + " (" + BuildShortCommitSHA + ")\nBuildDate: " + BuildDate + "\nhttps://infraql.io\n")

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&runtimeCtx.CPUProfile, "cpuprofile", "", "cpuprofile file, none if empty")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.LogLevelStr, "loglevel", "warn", "loglevel")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.PrivateKeyEnvVar, "privatekeyenvvar", "", "env var containing pem format private key")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.PrivateKeyPath, "privatekeypath", "", "file path for pem format private key")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.PublicKeyPath, "publickeypath", "", "file path for public key")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.CertificatePath, "certificatepath", "", "file path for certificate")
	rootCmd.PersistentFlags().StringVarP(&runtimeCtx.OutFilePath, "outfile", "o", "", "file path for outfile")
	rootCmd.PersistentFlags().BoolVarP(&runtimeCtx.Strict, "strict", "", false, "strict mode")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.PrivateKeyFormat, "privatekeyformat", "pem", "format for private key")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.PublicKeyFormat, "publickeyformat", "pem", "format for public key")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.CertificateFormat, "certificateformat", "pem", "format for certificate")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.OutFileFormat, "outfileformat", "", "format for outfile")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.SignatureTime, "signaturetime", "now", "timestamp to include in signature")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.Delimiter, "delimiter", ",", "delimiter for list fields")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.EmailAddresses, "certificate.emails", "javen@stackql.io", "delimited list of emails")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.URIs, "certificate.urls", "https://stackql.io", "delimited list of urls")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.Organization, "certificate.organization", "StackQL Studios", "delimited list of org strings")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.FirstName, "certificate.firstname", ",", "first name")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.LastName, "certificate.lastname", "", "last name")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.Host, "certificate.host", "stackql.io", "host")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.CommonName, "certificate.commonname", "Jeffrey Aven", "common name")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.LocalCertsPath, "localcerts.signingbundle", "", "path to file containing **only** pem certificate bundle used to sign registry files.  Empty string means local certs will be ignored altogether.")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.LocalCABundlePath, "localcerts.cabundle", "", "path to file containing **only** pem certificate bundle to be used as CA.  Empty string denotes no change.")
	rootCmd.PersistentFlags().StringVar(&runtimeCtx.LocalCertsRegex, "localcerts.regex", ".*", "regex to match when local certs should be used.  Only applies when localcerts.path nonempty.")

	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(certVerifyCmd)
	rootCmd.AddCommand(createKeysCmd)

}

func setLogLevel() {
	logLevel, err := log.ParseLevel(runtimeCtx.LogLevelStr)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(logLevel)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {

	setLogLevel()

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
