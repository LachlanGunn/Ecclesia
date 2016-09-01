package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"requestor/directory"
	"verifier/certificate"
)

func main() {
	verifier_count := flag.Int("verifiers", 10, "Number of verifiers to draw")
	noca := flag.Bool("noca", false, "do not require a valid certificate chain")
	flag.Parse()
	args := flag.Args()

	if len(args) != 3 {
		fmt.Fprintf(os.Stderr,
			"USAGE: validate_certificate <directory> <certificate> <identity>\n")
		os.Exit(1)
	}

	directory_filename := args[0]
	certificate_filename := args[1]

	fh, err := os.Open(directory_filename)
	defer fh.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not open directory file: %s\n", err.Error())
		os.Exit(1)
	}

	data, err := ioutil.ReadAll(fh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read directory file.\n")
		os.Exit(1)
	}

	fh_cert, err := os.Open(certificate_filename)
	defer fh_cert.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not open certificate file: %s\n", err.Error())
		os.Exit(1)
	}

	certificate_data, err := ioutil.ReadAll(fh_cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read certificate file.\n")
		os.Exit(1)
	}

	dir, err := directory.ParseDirectory(data)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not parse directory: %s\n", err.Error())
		os.Exit(1)
	}

	verifiers, err :=
		dir.RandomVerifiers(args[2], *verifier_count)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Error selecting verifiers: %s\n", err.Error())
		os.Exit(1)
	}

	certificates_original := make([]json.RawMessage, *verifier_count)
	json.Unmarshal(certificate_data, &certificates_original)

	if len(certificates_original) != *verifier_count {
		fmt.Fprintln(os.Stderr, "Incorrect verifier count")
		os.Exit(1)
	}

	x509_cert, err := certificate.GetCertificate(args[2], *noca)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting certificate: %s\n",
			err.Error())
		os.Exit(1)
	}
	fingerprint_sha1 := sha1.Sum(x509_cert.Raw)
	fingerprint_sha256 := sha256.Sum256(x509_cert.Raw)

	fingerprint_sha1_hex := hex.EncodeToString(fingerprint_sha1[:])
	fingerprint_sha256_hex := hex.EncodeToString(fingerprint_sha256[:])
	for i, v := range certificates_original {
		cert, err := directory.ParseCertificate(
			v, verifiers[i].PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Certificate error: %s\n",
				err.Error())
			os.Exit(1)
		}

		if cert.Host != args[2] {
			fmt.Fprintln(os.Stderr, "Incorrect host")
			os.Exit(1)
		}

		if cert.FingerprintSHA1 != fingerprint_sha1_hex ||
			cert.FingerprintSHA256 != fingerprint_sha256_hex {

			fmt.Fprintln(os.Stderr, "Non-matching fingerprint")
			os.Exit(1)
		}

		time_since_validity := cert.Time.Sub(dir.Time)
		if !(0 <= time_since_validity &&
			time_since_validity <= dir.Validity) {
			fmt.Fprintln(os.Stderr,
				"Certificate issued outside directory validity")
			os.Exit(1)
		}
	}

}
