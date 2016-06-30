package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"requestor/directory"
)

func main() {
	verifier_count := flag.Int("verifiers",10,"Number of verifiers to draw")
	flag.Parse()
	args := flag.Args()

	if len(args) != 2 {
		fmt.Fprintf(os.Stderr,
			"USAGE: get_certificate <directory> <identity>\n")
		os.Exit(1)
	}

	directory_filename := args[0]

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

	var dir directory.Directory
	err = json.Unmarshal(data, &dir)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not parse directory: %s\n", err.Error())
		os.Exit(1)
	}

	verifiers, err :=
		dir.RandomVerifiers(args[1], *verifier_count)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Error selecting verifiers: %s\n", err.Error())
		os.Exit(1)
	}

	certificates := make([]json.RawMessage, *verifier_count)
	for i, v := range(verifiers) {
		response, err := http.PostForm(
			"http://" + v.Address + "/verify",
			url.Values{"host": {args[1]}})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			continue
		}
		body, err := ioutil.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			continue
		}

		fmt.Fprintln(os.Stderr, base64.StdEncoding.EncodeToString(v.PublicKey))

		_, err = directory.ParseCertificate(body, v.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"Error parsing certificate: %s.\n", err.Error())
			os.Exit(1)
		}

		certificates[i] = json.RawMessage(body)
	}

	json_certificate, err := json.Marshal(certificates)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshalling error: %s\n", err.Error())
		os.Exit(1)
	}

	os.Stdout.Write(json_certificate)
}
