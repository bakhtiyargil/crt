package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "To import certificate",
	Long:  "This command will import certificate",
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		cacertpath, _ := cmd.Flags().GetString("cacertspath")
		javaHome, _ := cmd.Flags().GetBool("java-home")
		system, _ := cmd.Flags().GetBool("system")

		if len(url) == 0 {
			fmt.Println("URL is required. Get help with -h or --help")
			return
		}

		if len(cacertpath) == 0 {
			if javaHome {
				cacertpath = "$JAVA_HOME/lib/security/cacerts"
			} else {
				fmt.Println("Provide either cacertspath or java-home flag")
				return
			}
		} else {
			if javaHome {
				fmt.Println("Provide either cacertspath or java-home flag, not both")
				return
			}
		}

		keytoolFunc(url, cacertpath, system)
	},
}

func init() {
	rootCmd.AddCommand(importCmd)

	importCmd.Flags().StringP("url", "u", "",
		"specify url you want to export certificates. Example: [\"vault.kapitalbank.az:443\"] -> [host]:[port]")
	importCmd.Flags().StringP("cacertspath", "c", "",
		"specify your cacerts file path. Example: [\"$JAVA_HOME/lib/security/cacerts\"]")
	importCmd.Flags().Bool("java-home", false, "use default $JAVA_HOME path to specify cacerts")
	importCmd.Flags().Bool("system", false, "use default SYSTEM trustore to store certificates")
}
