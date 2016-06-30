package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"time"
	
	"golang.org/x/crypto/ed25519"

	"requestor/randomset"
)

type Certificate struct {
	Host        []byte
	Certificate []byte
	Signature   []byte
}

type SignedDirectory struct {
	Directory []byte
	PublicKey ed25519.PublicKey
	Signature []byte
}

type DirectoryBody struct {
	Verifiers     []DirectoryEntry
	LastDirectory string
	Time          time.Time
	Validity      time.Duration
}

type DirectoryEntry struct {
	Commit          []byte
	Reveal          []byte
	Signature       []byte
}

type VerifierCommit struct {
	JSON        []byte
	Signature   []byte
}

type VerifierReveal struct {
	PublicKey   string
	RevealValue string
}

type Verifier struct {
	PublicKey   ed25519.PublicKey
	Address     string
	Time        time.Time
	CommitValue []byte
}


func main() {
	k := flag.Int("k", 1, "Verifiers needed per certificate")
	flag.Parse()

	args := flag.Args()
	dirfile := args[0]

	fh, err := os.Open(dirfile)
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
		
	var directory_container SignedDirectory
	err = json.Unmarshal(data, &directory_container)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not parse directory file: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Directory public key: %s\n",
		base64.StdEncoding.EncodeToString(
			directory_container.PublicKey))

	signature_valid := ed25519.Verify(directory_container.PublicKey,
		directory_container.Directory, directory_container.Signature)
	if signature_valid {
		fmt.Println("Signature: valid")
	} else {
		fmt.Println("Signature: invalid")
	}

	var directory DirectoryBody
	err = json.Unmarshal(directory_container.Directory, &directory)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not parse directory body: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Valid %s from %s\n",
		directory.Validity.String(),
		directory.Time.Format("2006-01-02 15:04"))


	fmt.Printf("Found %d verifiers.\n", len(directory.Verifiers))

	var verifier_commit_prev Verifier

	hash_context := sha256.New()
	reveal_valid := true
	for index, verifier_json := range directory.Verifiers {
		var verifier_commit Verifier
		err = json.Unmarshal(verifier_json.Commit, &verifier_commit)
		if err != nil {
			fmt.Println("Verifier: invalid")
			reveal_valid = false
		}

		signature_valid := ed25519.Verify(verifier_commit.PublicKey,
			verifier_json.Commit, verifier_json.Signature)

		fmt.Println()
		fmt.Println(verifier_commit.Address,
			base64.StdEncoding.EncodeToString(
				verifier_commit.PublicKey))

		if index > 0 {
			if bytes.Compare(verifier_commit.PublicKey,
				verifier_commit_prev.PublicKey) < 0 {

				fmt.Println("    Order: invalid")
				reveal_valid = false
			} else {
				fmt.Println("    Order: correct")
			}
		}

		if signature_valid {
			fmt.Println("    Signature: valid")
		} else {
			fmt.Println("    Signature: invalid")
		}

		fmt.Printf("    Timestamp: %s\n", verifier_commit.Time)

		if err != nil {
			fmt.Println("    Reveal: invalid")
			reveal_valid = false
		} else {
			hashed_reveal := sha256.Sum256(verifier_json.Reveal)
			var valid_string string
			if bytes.Equal(hashed_reveal[:],
				verifier_commit.CommitValue) {
				valid_string = "(valid)"
			} else {
				valid_string = "(invalid)"
				reveal_valid = false
			}
			fmt.Printf("    Reveal: %s... %s\n",
				hex.EncodeToString(verifier_json.Reveal[0:10]),
				valid_string)
			fmt.Printf("    Commit: %s...\n",
				hex.EncodeToString(
					verifier_commit.CommitValue[0:10]))

			hash_context.Write(verifier_json.Reveal)
		}

		verifier_commit_prev = verifier_commit
	}

	var valid_string string
	if reveal_valid {
		valid_string = "(valid)"
	} else {
		valid_string = "(invalid)"
	}

	final_shared_random_value := hash_context.Sum(nil)
	fmt.Printf("\nShared random value: %s %s\n",
		hex.EncodeToString(final_shared_random_value), valid_string)

	fmt.Println("\nIdentity verifier sets:")
	for i := 1; i < len(args); i++ {
		verifiers, err := randomset.RandomSubset(
			final_shared_random_value,
			[]byte(args[i]),
			len(directory.Verifiers),
			*k)
		if err != nil {
			fmt.Printf("    %s: error (%s)\n", args[i], err.Error())
			continue
		} else {
			fmt.Printf("    %s: ", args[i])
			fmt.Println(verifiers)
		}
	}
}
