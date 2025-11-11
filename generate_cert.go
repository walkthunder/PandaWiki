package main
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// Create certificate template with proper X.509 v3 extensions
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Printf("failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "pandawiki.docs.baizhi.cloud",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Certificate valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"pandawiki.docs.baizhi.cloud"},
	}

	// Sign certificate with private key
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		fmt.Printf("failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	// Write certificate file with appropriate permissions
	certFile, err := os.Create("./web/admin/ssl/panda-wiki.crt")
	if err != nil {
		fmt.Printf("failed to create cert file: %v\n", err)
		os.Exit(1)
	}
	defer certFile.Close()

	if err := certFile.Chmod(0644); err != nil {
		fmt.Printf("failed to set cert file permissions: %v\n", err)
		os.Exit(1)
	}

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		fmt.Printf("failed to encode certificate: %v\n", err)
		os.Exit(1)
	}

	// Write private key file with appropriate permissions
	keyFile, err := os.Create("./web/admin/ssl/panda-wiki.key")
	if err != nil {
		fmt.Printf("failed to create key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	if err := keyFile.Chmod(0600); err != nil {
		fmt.Printf("failed to set key file permissions: %v\n", err)
		os.Exit(1)
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		fmt.Printf("failed to encode private key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("证书生成成功")
}