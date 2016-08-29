package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"time"
	
	"golang.org/x/crypto/ed25519"
	"github.com/golang/protobuf/proto"

	"protobufs"
	"requestor/randomset"
	"shared/protocol_common"
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
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr,
			"USAGE: read_directory [-k <verifiers>] <directory> "+
			"<identity> <identity> ...\n")
		os.Exit(1)
	}

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
		
	directory_container, err := protocol_common.UnpackSignedData(
		data, func(ed25519.PublicKey)bool{return true})
	if err != nil {
		switch err.(type) {
		case protocol_common.BadSignatureError:
			fmt.Fprintln(os.Stderr, "Signature: invalid")
		default:
			fmt.Fprintf(os.Stderr,
				"Could not parse directory file: %s\n",
				err.Error())
			os.Exit(1)
		}
	} else {
		fmt.Println("Signature: invalid")
	}

	fmt.Printf("Directory public key: %s\n",
		base64.StdEncoding.EncodeToString(
			directory_container.PublicKey))

	var directory protobufs.Directory
	err = proto.Unmarshal(directory_container.Data, &directory)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Could not parse directory body: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Valid %s from %s\n",
		directory.Validity,
		directory.Time)


	fmt.Printf("Found %d verifiers.\n", len(directory.DirectoryEntries))

	var verifier_commit_prev protobufs.VerifierCommit

	hash_context := sha256.New()
	reveal_valid := true
	for index, directory_entry := range directory.DirectoryEntries {

		err := protocol_common.VerifySignedData(
			*directory_entry.VerifierCommit,
			func(key ed25519.PublicKey) bool {
				return true
			})

		signature_valid := true
		if err != nil {
			switch err.(type) {
			case protocol_common.BadSignatureError:
				signature_valid = false
			default:
				fmt.Printf("Signature package: invalid (%s)\n",
					err.Error())
				
				reveal_valid = false
				continue
			}
		}

		var verifier_commit protobufs.VerifierCommit
		err = proto.Unmarshal(
			directory_entry.VerifierCommit.Data,
			&verifier_commit)
		if err != nil {
			fmt.Println("Verifier: Invalid")
			reveal_valid = false
			continue
		}

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
			hashed_reveal := sha256.Sum256(directory_entry.VerifierReveal)
			var valid_string string
			if bytes.Equal(hashed_reveal[:],
				verifier_commit.CommitValue) {
				valid_string = "(valid)"
			} else {
				valid_string = "(invalid)"
				reveal_valid = false
			}
			fmt.Printf("    Reveal: %s... %s\n",
				hex.EncodeToString(directory_entry.VerifierReveal[0:10]),
				valid_string)
			fmt.Printf("    Commit: %s...\n",
				hex.EncodeToString(
					verifier_commit.CommitValue[0:10]))

			hash_context.Write(directory_entry.VerifierReveal)
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

	if len(args) >= 2 {
		fmt.Println("\nIdentity verifier sets:")
	}

	for i := 1; i < len(args); i++ {
		verifiers, err := randomset.RandomSubset(
			final_shared_random_value,
			[]byte(args[i]),
			len(directory.DirectoryEntries),
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
