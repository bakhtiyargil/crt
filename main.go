package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func main() {
	Execute()
}

func keytoolFunc(url string, cacertpath string, system bool) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", url, conf)
	errAndExit("Error in dial: %v\n", err)

	defer func(conn *tls.Conn) {
		err := conn.Close()
		errAndExit("Error in connection closing: %v\n", err)
	}(conn)

	rootCAs, err := x509.SystemCertPool()
	errAndExit("Error getting system certificate pool: %v\n", err)

	certs := conn.ConnectionState().PeerCertificates

	for i, cert := range certs {
		certFile, err := os.CreateTemp("", "cert")
		errAndExit("Error creating temp file: %v\n", err)

		defer func(certFile *os.File) {
			err := certFile.Close()
			errAndExit("Error in file closing: %v\n", err)
		}(certFile)
		defer func(name string) {
			err := os.Remove(name)
			errAndExit("Error in file removing: %v\n", err)
		}(certFile.Name())

		if system {
			rootCAs.AddCert(cert)
		}

		err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		errAndExit("Error writing certificate to file: %v\n", err)

		cmd := exec.Command("sudo", "keytool", "-import", "-alias", "CRT_"+url+strconv.Itoa(i),
			"-keystore", cacertpath,
			"-file", certFile.Name(), "-storepass", "changeit", "-noprompt")
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
