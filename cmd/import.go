package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"strconv"
)

const (
	UrlFlag             = "url"
	SystemFlag          = "system"
	JavaHomeFlag        = "java-home"
	CacertsFlag         = "cacertspath"
	JavaHomeCacertsPath = "$JAVA_HOME/lib/security/cacerts"
	EncodeType          = "CERTIFICATE"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Imports certificate.",
	Long:  "This command is going to help import the certificate.",
	Run:   importFunction(),
}

func init() {
	rootCmd.AddCommand(importCmd)
	addFlags()
}

func addFlags() {
	importCmd.Flags().StringP(UrlFlag, "u", "",
		"Specify the URL from which you want to export certificates. Example: [\"vault.kapitalbank.az:443\"] -> [host]:[port]")

	importCmd.Flags().StringP(CacertsFlag, "c", "",
		"Specify the path to your cacerts file. Example: [\"$JAVA_HOME/lib/security/cacerts\"]")

	importCmd.Flags().Bool(JavaHomeFlag, false,
		"Use the default $JAVA_HOME path to specify the cacerts file.")

	importCmd.Flags().Bool(SystemFlag, false,
		"Use the default system truststore to store certificates.")
}

func importFunction() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString(UrlFlag)
		system, _ := cmd.Flags().GetBool(SystemFlag)
		javaHome, _ := cmd.Flags().GetBool(JavaHomeFlag)
		cacertpath, _ := cmd.Flags().GetString(CacertsFlag)
		if len(url) == 0 {
			fmt.Println("URL is required. Get help with -h or --help.")
			return
		}
		if javaHome {
			if len(cacertpath) == 0 {
				cacertpath = JavaHomeCacertsPath
			} else {
				fmt.Println("Provide either cacertspath or java-home flag, not both")
				return
			}
		} else if len(cacertpath) == 0 {
			fmt.Println("Provide either cacertspath or java-home flag")
			return
		}

		addCertificate(url, cacertpath, system)
	}
}

func addCertificate(url string, cacertpath string, system bool) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", url, conf)
	errAndExit("Error in dial TCP: %v\n", err)

	defer func(conn *tls.Conn) {
		err := conn.Close()
		errAndExit("Error in connection closing: %v\n", err)
	}(conn)

	certs := conn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		tempCert, err := os.CreateTemp("", "cert")
		errAndExit("Error creating temp file: %v\n", err)

		defer tempCert.Close()
		defer os.Remove(tempCert.Name())

		if system {
			rootCAs, err := x509.SystemCertPool()
			errAndExit("Error getting system certificate pool: %v\n", err)
			rootCAs.AddCert(cert)
		}

		err = pem.Encode(tempCert, &pem.Block{Type: EncodeType, Bytes: cert.Raw})
		errAndExit("Error writing certificate to file: %v\n", err)

		cmd := exec.Command("sudo",
			"keytool",
			"-import",
			"-alias",
			"CRT_"+url+strconv.Itoa(i),
			"-keystore", cacertpath,
			"-file", tempCert.Name(),
			"-storepass",
			"changeit",
			"-noprompt")
		err = cmd.Run()
		errAndExit("Error running keytool: %v\n", err)
	}
	fmt.Printf("Certificates added successfully!")
	return
}

func errAndExit(msg string, err error) {
	if err != nil {
		fmt.Printf(msg, err)
		os.Exit(1)
	}
}
