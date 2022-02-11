package argparse

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/stackql/stackql-provider-registry/signing/Ed25519/app/edcrypto"
)

func printErrorAndExitOneIfNil(subject interface{}, msg string) {
	if subject == nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintln(msg))
		os.Exit(1)
	}
}

func printErrorAndExitOneIfError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintln(err.Error()))
		os.Exit(1)
	}
}

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "sign",
	Short: "Simple Ed25519 sign",
	Long:  `Simple Ed25519 sign`,
	Run: func(cmd *cobra.Command, args []string) {

		cb := func() {
			if len(args) == 0 || args[0] == "" {
				cmd.Help()
				os.Exit(0)
			}

			b, err := edcrypto.SignFile(runtimeCtx.PrivateKeyPath, runtimeCtx.PrivateKeyFormat, args[0])
			printErrorAndExitOneIfError(err)
			printErrorAndExitOneIfNil(b, "no signature created")
			fmt.Printf("\nhex encoded signature = '%s'\n", hex.EncodeToString(b))
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
