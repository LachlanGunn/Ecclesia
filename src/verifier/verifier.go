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

	"github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ed25519"
)

var log = logrus.New()

func main() {
	directory := flag.String("directory", "localhost:8080", "directory server")
	secret := flag.String("key", "", "secret key input file")
	bind := flag.String("bind", ":8081", "bind address/port")
	advertise := flag.String("advertise", "", "advertised address/port")
	novalidate := flag.Bool("novalidate", false, "do not validate certificates")
	debug := flag.Bool("debug", false, "log debugging information.")
	quiet := flag.Bool("quiet", false, "only log errors.  Overrides -debug.")
	flag.Parse()

	if *debug == true {
		log.Level = logrus.DebugLevel
	}

	if *quiet == true {
		log.Level = logrus.ErrorLevel
	}

	secret_key := get_keys(*secret)

	r := gin.New()
	r.Use(gin.Recovery())

	r.POST("/verify", func(c *gin.Context) {
		certificate_report(c, secret_key, *novalidate)
	})

	if *advertise == "" {
		*advertise = *bind
	}

	go goroutine_registration(*directory, secret_key, *advertise)

	r.Run(*bind)
}

func get_keys(secret string) ed25519.PrivateKey {

	if secret == "" {
		fmt.Fprintf(os.Stderr,
			"USAGE: main -key <file>\n")
		os.Exit(1)
	}

	logging_context := logrus.Fields{
		"KeyFile": secret,
	}

	fh_secret, error := os.OpenFile(secret, os.O_RDONLY|os.O_CREATE, 0600)
	if error != nil {
		logging_context["Error"] = error
		log.WithFields(logging_context).Fatal(
			"Failed to open keyfile.")
	}
	defer fh_secret.Close()

	secret_key_bytes, err := ioutil.ReadAll(fh_secret)
	if err != nil {
		logging_context["Error"] = err
		log.WithFields(logging_context).Fatal(
			"Failed to read secret key.")
	}

	secret_key_bytes_decoded, err :=
		base64.StdEncoding.DecodeString(string(secret_key_bytes))
	if err != nil {
		logging_context["Error"] = err
		log.WithFields(logging_context).Fatal(
			"Could not decode secret key.")
	}

	return ed25519.PrivateKey(secret_key_bytes_decoded)
}

func certificate_report(c *gin.Context, secret_key ed25519.PrivateKey,
	novalidate bool) {

	logging_context := logrus.Fields{
		"ClientIP": c.ClientIP(),
	}

	host := c.PostForm("host")
	if host == "" {
		c.JSON(400, gin.H{"result": "failure",
			"reason": "no host provided"})
		log.WithFields(logging_context).Error(
			"certificate_report: No host provided.")
		return
	}

	logging_context["HostToVerify"] = host

	certificate, err := certificate.GetCertificate(host, novalidate)
	if err != nil {
		logging_context["Error"] = err
		log.WithFields(logging_context).Error(
			"certificate_report: Certificate acquisition failed.")
		c.JSON(500, gin.H{"result": "failure",
			"reason": "failed to obtain valid certificate"})
		return
	}

	fingerprint := sha1.Sum(certificate.Raw)
	fingerprint_hex := hex.EncodeToString(fingerprint[:])

	fingerprint_sha256 := sha256.Sum256(certificate.Raw)
	fingerprint_sha256_hex := hex.EncodeToString(fingerprint_sha256[:])

	certificate_contents_json, err := json.Marshal(struct {
		Time              time.Time
		Host              string
		FingerprintSHA1   string
		FingerprintSHA256 string
	}{time.Now(), host, fingerprint_hex, fingerprint_sha256_hex})

	certificate_json, err := json.Marshal(struct {
		Certificate []byte
		Signature   []byte
	}{certificate_contents_json,
		ed25519.Sign(secret_key, certificate_contents_json)})

	c.Data(200, "application/json", certificate_json)
	log.WithFields(logging_context).Info(
		"certificate_report: Issued certificate.")
}

func goroutine_registration(
	directory string,
	secret_key ed25519.PrivateKey,
	bind_address string) {

	first := true

	for {
		err := registration.Register(
			directory, secret_key, bind_address, first, log)
		first = false

		if err != nil {
			log.WithFields(logrus.Fields{
				"Error": err,
			}).Error("Registration error.")
			time.Sleep(5 * time.Second)
		}
	}
}
