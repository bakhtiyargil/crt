package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

const (
	UrlFlag             = "url"
	SystemFlag          = "system"
	JavaHomeFlag        = "java-home"
	CacertsPathFlag     = "cacertspath"
	CacertsPassFlag     = "cacertspass"
	JavaHomeCacertsPath = "$JAVA_HOME/lib/security/cacerts"
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
		"specify the URL from which you want to export certificates. Example: [\"github.com:443\"] -> [host]:[port]")

	importCmd.Flags().StringP(CacertsPathFlag, "c", "",
		"specify the path to your cacerts file. Example: [\"$JAVA_HOME/lib/security/cacerts\"]")

	importCmd.Flags().StringP(CacertsPassFlag, "p", "",
		"specify the password for your cacerts file.")

	importCmd.Flags().Bool(JavaHomeFlag, false,
		"use the default $JAVA_HOME path to specify the cacerts file.")

	importCmd.Flags().Bool(SystemFlag, false,
		"use the default system truststore to store certificates.")
}

func importFunction() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString(UrlFlag)
		system, _ := cmd.Flags().GetBool(SystemFlag)
		javaHome, _ := cmd.Flags().GetBool(JavaHomeFlag)
		cacertpath, _ := cmd.Flags().GetString(CacertsPathFlag)
		cacertpass, _ := cmd.Flags().GetString(CacertsPassFlag)

		if len(url) == 0 {
			fmt.Println("URL is required. Get help with -h or --help.")
			return
		}
		if len(cacertpass) == 0 {
			fmt.Println("Password is required. Get help with -h or --help.")
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

		AddCertificate(url, cacertpath, system, cacertpass)
	}
}

func AddCertificate(hostPort string, cacertpath string, system bool, password string) {
	conf := &tls.Config{}
	conn, err := tls.Dial("tcp", hostPort, conf)
	errAndExit("error in dial TCP: %v\n", err)
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			errAndExit("warning: error closing connection: %v\n", cErr)
		}
	}()
	certs := conn.ConnectionState().PeerCertificates

	data, err := os.ReadFile(cacertpath)
	errAndExit("error reading truststore: %v\n", err)

	if password == "changeit" {
		password = ""
	}
	existingCerts, err := pkcs12.DecodeTrustStore(data, password)
	if err != nil {
		errAndExit("cannot decode PKCS12 truststore: %v\n", err)
	}

	fmt.Printf("Existing truststore has %d certs\n", len(existingCerts))

	if system {
		rootCAs, err := x509.SystemCertPool()
		errAndExit("Error getting system certificate pool: %v\n", err)
		for _, cert := range certs {
			rootCAs.AddCert(cert)
		}
	}

	for i, newCert := range certs {
		if !containsCert(existingCerts, newCert) {
			existingCerts = append(existingCerts, newCert)
			fmt.Printf("Added certificate: %s\n", newCert.Subject.CommonName)
		} else {
			fmt.Printf("Certificate already exists: %s\n", newCert.Subject.CommonName)
		}
		loadingAnimation(i+1, len(certs))
	}

	newData, err := pkcs12.Passwordless.EncodeTrustStore(existingCerts, password)
	if err != nil {
		errAndExit("error encoding truststore: %v\n", err)
	}

	err = os.WriteFile(cacertpath, newData, 0644)
	errAndExit("error writing truststore: %v\n", err)

	fmt.Println("\nCertificates added successfully!")
}

func containsCert(certs []*x509.Certificate, newCert *x509.Certificate) bool {
	for _, c := range certs {
		if c.Equal(newCert) {
			return true
		}
	}
	return false
}

func errAndExit(msg string, err error) {
	if err != nil {
		fmt.Printf(msg, err)
		os.Exit(1)
	}
}

func loadingAnimation(jobsDone, jobsMax int) {
	barMax := 50
	var barCurrent int
	barDiff := barMax / jobsMax
	if jobsDone == jobsMax {
		for i := 0; i < barMax; i++ {
			fmt.Print("#")
		}
	} else {
		barCurrent = jobsDone * (barDiff)

		for i := 0; i < barCurrent; i++ {
			fmt.Print("#")
		}

		for i := barCurrent; i < barMax; i++ {
			fmt.Print(".")
		}
		time.Sleep(300 * time.Millisecond)
		if jobsDone != jobsMax {
			//clear stdout
			fmt.Print("\033[2K\r")
		}
	}
}
