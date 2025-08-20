package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "crt",
	Short: "crt is a CLI tool importing certificate from URL to truststore.",
	Long:  "crt is a CLI tool importing certificate to truststore. You can use this for PKIX problems :).",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to crt CLI! Use -h to see available commands.")
	},
}

func Execute() error {
	return rootCmd.Execute()
}
