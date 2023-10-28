package main

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "crt",
	Short: `crt is a CLI tool importing certificate from URL to truststore.`,
	Long:  `crt is a CLI tool importing certificate to truststore. You can use this for PKIX problems :).`,
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	err := rootCmd.Execute()

	if err != nil {
		print(err)
		os.Exit(1)
	}
}
