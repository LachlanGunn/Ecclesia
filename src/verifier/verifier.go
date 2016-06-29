package main

import (
	"verifier/certificate"
	"verifier/registration"

	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ed25519"
)

func main() {
	secret    := flag.String("key", "", "secret key input file")
	bind      := flag.String("bind", ":8081", "bind address/port")
	advertise := flag.String("advertise", "", "advertised address/port")
	flag.Parse()
	
	secret_key := get_keys(*secret)

	r := gin.Default()

	r.POST("/verify", func(c *gin.Context) {
		certificate_report(c, secret_key)
	})

	if *advertise == "" {
		*advertise = *bind
	}

	go goroutine_registration(secret_key, *advertise)

	r.Run(*bind)
}

func get_keys(secret string) ed25519.PrivateKey {

	if secret == "" {
		fmt.Fprintf(os.Stderr,
			"USAGE: main -key <file>\n")
		os.Exit(1)
	}

	fh_secret, error := os.OpenFile(secret, os.O_RDONLY|os.O_CREATE, 0600)
	if error != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s\n", secret)
		os.Exit(1)
	}
	defer fh_secret.Close()

	secret_key_bytes, err := ioutil.ReadAll(fh_secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read secret key.\n")
		os.Exit(1)
	}

	secret_key_bytes_decoded, err :=
		base64.StdEncoding.DecodeString(string(secret_key_bytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decode secret key: %s\n",
			err.Error())
	}

	return ed25519.PrivateKey(secret_key_bytes_decoded)
}

func certificate_report(c *gin.Context, secret_key ed25519.PrivateKey) {
	host := c.PostForm("host")
	if host == "" {
		c.String(400, "")
		return
	}
	
	certificate, err := certificate.GetCertificate(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		os.Exit(1)
	}

	fingerprint := sha1.Sum(certificate.Raw)
	fingerprint_hex := hex.EncodeToString(fingerprint[:])

	fingerprint_sha256 := sha256.Sum256(certificate.Raw)
	fingerprint_sha256_hex := hex.EncodeToString(fingerprint_sha256[:])
	
	fmt.Printf("%s ... (%d -> %d)\n", fingerprint_hex,
		len(certificate.Raw), len(fingerprint))

	certificate_contents_json, err := json.Marshal(struct{
		Time time.Time
		Host string
		FingerprintSHA1   string
		FingerprintSHA256 string
	}{time.Now(), host, fingerprint_hex, fingerprint_sha256_hex})

	certificate_json, err := json.Marshal(struct{
		Certificate []byte
		Signature   []byte
	}{certificate_contents_json,
		ed25519.Sign(secret_key, certificate_contents_json)})

	c.Data(200, "application/json", certificate_json)
}

func goroutine_registration(secret_key ed25519.PrivateKey,
	bind_address string) {

	first := true
	
	for {
		err := registration.Register(secret_key, bind_address, first)
		first = false

		if err != nil {
			fmt.Fprintf(os.Stderr,
				"Registration error: %s\n", err.Error())
			time.Sleep(5*time.Second)
		} else {
			fmt.Fprintf(os.Stderr, "Successfully registered.\n")
		}
	}
}
