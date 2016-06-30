package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"requestor/directory"
)

func main() {
	verifier_count := flag.Int("verifiers",10,"Number of verifiers to draw")
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr,
			"USAGE: get_verifiers <directory> <identity>\n")
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

	var directory directory.Directory
	err = json.Unmarshal(data, &directory)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not parse directory: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(directory.RandomValue))

	for i := 1; i < len(args); i++ {
		fmt.Println(args[i])
		verifiers, err :=
			directory.RandomVerifiers(args[i], *verifier_count)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"Error selecting verifiers: %s\n", err.Error())
			continue
		}
		for _, v := range(verifiers) {
			fmt.Printf("    %s\n", v.Address)
		}
	}
}
