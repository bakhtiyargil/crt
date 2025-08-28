package main

import (
	"crt/cmd"
)

func main() {
	cmd.AddCertificate("google.com:443",
		"/Users/karimovbaxtiyar/.sdkman/candidates/java/current/lib/security/cacerts",
		false,
		"changeit")

	/*	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}*/
}
