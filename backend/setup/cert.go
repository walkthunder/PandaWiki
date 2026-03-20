package setup

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

var (
	keyFile  = getSSLPath("panda-wiki.key") // Key file path
	certFile = getSSLPath("panda-wiki.crt") // Certificate file path
)

// getSSLPath returns the SSL file path based on environment
func getSSLPath(filename string) string {
	// Check if SSL_DIR environment variable is set (for local development)
	if sslDir := os.Getenv("SSL_DIR"); sslDir != "" {
		return sslDir + "/" + filename
	}
	// Default to Docker container path
	return "/app/etc/nginx/ssl/" + filename
}

// getSSLDir returns the SSL directory path based on environment
func getSSLDir() string {
	if sslDir := os.Getenv("SSL_DIR"); sslDir != "" {
		return sslDir
	}
	return "/app/etc/nginx/ssl"
}

// check init cert
func CheckInitCert() error {
	// Check both key and cert files
	keyExists := false
	certExists := false

	if _, err := os.Stat(keyFile); err == nil {
		keyExists = true
	}

	if _, err := os.Stat(certFile); err == nil {
		certExists = true
	}

	// If either file is missing, recreate both
	if !keyExists || !certExists {
		return createSelfSignedCerts()
	}

	return nil
}

func createSelfSignedCerts() error {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "pandawiki.docs.baizhi.cloud",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Certificate valid for 10 year
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"pandawiki.docs.baizhi.cloud"},
	}

	// Sign certificate with private key
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// ensure SSL directory exists
	sslDir := getSSLDir()
	if err := os.MkdirAll(sslDir, 0o755); err != nil {
		return fmt.Errorf("failed to create ssl dir: %v", err)
	}

	// Write certificate file with appropriate permissions
	certFilePath := sslDir + "/panda-wiki.crt"
	certFile, err := os.Create(certFilePath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certFile.Close()

	// Set certificate file permissions to 644 (readable by all)
	if err := certFile.Chmod(0o644); err != nil {
		return fmt.Errorf("failed to set cert file permissions: %v", err)
	}

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %v", err)
	}

	// Write private key file with appropriate permissions
	keyFilePath := sslDir + "/panda-wiki.key"
	keyFile, err := os.Create(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyFile.Close()

	// Set private key file permissions to 600 (owner read/write)
	if err := keyFile.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %v", err)
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	return nil
}
