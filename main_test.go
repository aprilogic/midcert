package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMitMDetection(t *testing.T) {
	// Create a test CA certificate
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA private key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test MitM CA"},
			CommonName:   "Test MitM CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Create a test server certificate signed by our CA
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate server private key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverCert, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Create a test server with our certificates
	server := &http.Server{
		Addr: "localhost:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS!"))
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{serverCert, caCert},
					PrivateKey:  serverPrivKey,
				},
			},
		},
	}

	// Start the server
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go server.ServeTLS(listener, "", "")
	time.Sleep(time.Second) // Give the server time to start

	// Get the actual address the server is listening on
	serverAddr := listener.Addr().String()
	serverURL := "https://" + serverAddr

	// Test the MitM detection
	outputFile := "test_certs.pem"
	defer os.Remove(outputFile)

	// Run the test
	os.Args = []string{"midcert", "-o", outputFile, "-url", serverURL}
	main()

	// Verify that the output file contains our CA certificate
	output, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	if len(output) == 0 {
		t.Error("Output file is empty")
	}

	// Print the PEM file contents in verbose mode
	t.Logf("Generated PEM file contents:\n%s", string(output))

	// Verify that the output contains our CA certificate
	caCertPEM := certToPEM(&x509.Certificate{
		Raw: caCert,
	})
	if !strings.Contains(string(output), caCertPEM) {
		t.Error("Output file does not contain the expected CA certificate")
	}
}
