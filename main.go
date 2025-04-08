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

const mozillaCABundleURL = "https://curl.se/ca/cacert.pem"

func main() {
	outputFile := flag.String("o", "", "Output file for the CA certificate chain (use - for stdout)")
	flag.Parse()

	// Download and load Mozilla's CA bundle
	resp, err := http.Get(mozillaCABundleURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading Mozilla CA bundle: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	caBundle, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading Mozilla CA bundle: %v\n", err)
		os.Exit(1)
	}

	mozillaPool := x509.NewCertPool()
	if !mozillaPool.AppendCertsFromPEM(caBundle) {
		fmt.Fprintf(os.Stderr, "Error parsing Mozilla CA bundle\n")
		os.Exit(1)
	}

	// Create a custom HTTP client that doesn't verify certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Try to connect to a known HTTPS site
	resp, err = client.Get("https://www.google.com")
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

	// Check for MitM proxy by examining certificate chain
	mitmDetected := false
	unknownCAs := []*x509.Certificate{}

	fmt.Printf("Certificate chain:\n")
	for i, cert := range certs {
		fmt.Printf("\nCertificate %d:\n", i+1)
		fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("  Issuer:  %s\n", cert.Issuer.CommonName)
		fmt.Printf("  Valid:   %s to %s\n", cert.NotBefore, cert.NotAfter)

		// Skip the leaf certificate (first in chain)
		if i == 0 {
			fmt.Printf("  ℹ️  Leaf certificate (not checked against trust store)\n")
			continue
		}

		// Check if this CA certificate is in Mozilla's trust store
		_, err = cert.Verify(x509.VerifyOptions{
			Roots: mozillaPool,
		})
		if err != nil {
			unknownCAs = append(unknownCAs, cert)
			mitmDetected = true
			fmt.Printf("  ⚠️  CA certificate not found in Mozilla trust store\n")
		} else {
			fmt.Printf("  ✓ CA certificate found in Mozilla trust store\n")
		}
	}

	if mitmDetected {
		fmt.Printf("\n⚠️  MitM proxy detected! Found %d unknown CA certificates.\n", len(unknownCAs))
	} else {
		fmt.Printf("\n✓ No MitM proxy detected - all CA certificates are trusted by Mozilla.\n")
	}

	// If output file is specified, save the certificates
	if *outputFile != "" && mitmDetected {
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

		// Write only the unknown CA certificates in PEM format (skip leaf certificate)
		for _, cert := range unknownCAs {
			pem := certToPEM(cert)
			if _, err := output.Write([]byte(pem)); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing certificate: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Printf("\nSaved %d unknown CA certificates to %s\n", len(unknownCAs), *outputFile)
	}
}

func certToPEM(cert *x509.Certificate) string {
	var pem strings.Builder
	pem.WriteString("-----BEGIN CERTIFICATE-----\n")
	pem.WriteString(base64.StdEncoding.EncodeToString(cert.Raw))
	pem.WriteString("\n-----END CERTIFICATE-----\n")
	return pem.String()
}
