package main

import (
	"fmt"
	"os"

	"github.com/stackql/stackql-provider-registry/signing/Ed25519/app/cmd/argparse"
)

func main() {
	if err := execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func execute() error {
	return argparse.Execute()
}
