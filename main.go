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
	if err != nil {
		fmt.Println(`Error in Dial!`, err)
		return
	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("Error in connection closing!", err)
		}
	}(conn)

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		fmt.Printf("Error getting system certificate pool: %v\n", err)
	}

	certs := conn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		certFile, err := os.CreateTemp("", "cert")
		if err != nil {
			fmt.Printf("Error creating temp file: %v\n", err)
			return
		}
		defer func(certFile *os.File) {
			err := certFile.Close()
			if err != nil {

			}
		}(certFile)
		defer func(name string) {
			err := os.Remove(name)
			if err != nil {

			}
		}(certFile.Name())

		if system {
			rootCAs.AddCert(cert)
		}

		err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			fmt.Printf("Error writing certificate to file: %v\n", err)
			return
		}

		cmd := exec.Command("sudo", "keytool", "-import", "-alias", "CRT_"+url+strconv.Itoa(i),
			"-keystore", cacertpath,
			"-file", certFile.Name(), "-storepass", "changeit", "-noprompt")
		err = cmd.Run()

		if err != nil {
			fmt.Printf("Error running keytool: %v\n", err)
			return
		}
	}
	fmt.Printf("Certificates added successfully!")
	return
}
