package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	outputFile := flag.String("o", "", "Output file for the CA certificate chain (use - for stdout)")
	flag.Parse()

	// Create a custom HTTP client that doesn't verify certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Try to connect to a known HTTPS site
	resp, err := client.Get("https://www.google.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to test site: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Get the certificate chain
	certs := resp.TLS.PeerCertificates
	if len(certs) == 0 {
		fmt.Println("No certificates found in the chain")
		os.Exit(1)
	}

	// Check if we're behind a MitM proxy
	// MitM proxies typically add their own certificate to the chain
	if len(certs) > 1 {
		fmt.Printf("Detected potential MitM proxy!\n\n")
		fmt.Printf("Certificate chain:\n")
		for i, cert := range certs {
			fmt.Printf("\nCertificate %d:\n", i+1)
			fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
			fmt.Printf("  Issuer:  %s\n", cert.Issuer.CommonName)
			fmt.Printf("  Valid:   %s to %s\n", cert.NotBefore, cert.NotAfter)
		}

		// If output file is specified, save the certificates
		if *outputFile != "" {
			var output io.Writer
			if *outputFile == "-" {
				output = os.Stdout
			} else {
				file, err := os.Create(*outputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
					os.Exit(1)
				}
				defer file.Close()
				output = file
			}

			// Write all certificates in PEM format
			for _, cert := range certs {
				pem := certToPEM(cert)
				if _, err := output.Write([]byte(pem)); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing certificate: %v\n", err)
					os.Exit(1)
				}
			}
		}
	} else {
		fmt.Println("No MitM proxy detected - only one certificate in chain")
	}
}

func certToPEM(cert *x509.Certificate) string {
	var pem strings.Builder
	pem.WriteString("-----BEGIN CERTIFICATE-----\n")
	pem.WriteString(base64.StdEncoding.EncodeToString(cert.Raw))
	pem.WriteString("\n-----END CERTIFICATE-----\n")
	return pem.String()
}
