package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"os"
)

func main() {
	public := flag.String("public", "", "public key output file")
	secret := flag.String("secret", "", "secret key output file")
	flag.Parse()

	if *public == "" || *secret == "" {
		fmt.Fprintf(os.Stderr,
			"USAGE: generate-key -public <file> -secret <file>\n")
		os.Exit(1)
	}

	fh_public, error := os.OpenFile(*public, os.O_WRONLY|os.O_CREATE, 0600)
	if error != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s\n", *public)
		os.Exit(1)
	}
	defer fh_public.Close()

	fh_secret, error := os.OpenFile(*secret, os.O_WRONLY|os.O_CREATE, 0600)
	if error != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s\n", *secret)
		os.Exit(1)
	}
	fh_secret.Chmod(0600)
	defer fh_secret.Close()

	public_key, secret_key, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key.\n")
		os.Exit(1)
	}

	public_key_encoded := base64.StdEncoding.EncodeToString(public_key)
	secret_key_encoded := base64.StdEncoding.EncodeToString(secret_key)

	fh_public.Write([]byte(public_key_encoded))
	fh_secret.Write([]byte(secret_key_encoded))
}
