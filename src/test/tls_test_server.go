package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

func make_certificate(host string) ([]byte, []byte) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Not really an organisation"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IsCA:                  true,
	}
	secret_key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate key.")
	}

	certificate_der, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &secret_key.PublicKey,
		secret_key)
	if err != nil {
		log.Fatal("Failed to create certificate:", err.Error())
	}

	certificate_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate_der,
		})
	key_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(secret_key),
		})

	return certificate_pem, key_pem
}

func server(config *tls.Config) {
	sock_listen, err := tls.Listen("tcp", ":7999", config)
	if err != nil {
		log.Fatal("Failed to listen on :7999:", err.Error())
	}
	for {
		sock_client, err := sock_listen.Accept()
		if err != nil {
			log.Println("Failed to accept connection.")
			continue
		}
		_, err = sock_client.Write([]byte("Hello!\n"))
		if err != nil {
			log.Println("Write failed:", err.Error())
		}
		sock_client.Close()
	}
}

func main() {
	cert_pem, secret_key_pem := make_certificate("localhost")
	cert, err := tls.X509KeyPair(cert_pem, secret_key_pem)
	if err != nil {
		log.Fatal("Failed to load key pair")
	}

	server(&tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
		ServerName: "localhost",
	})
}
