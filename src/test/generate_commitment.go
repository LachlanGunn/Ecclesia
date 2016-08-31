package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"protobufs"

	"golang.org/x/crypto/ed25519"
	"github.com/golang/protobuf/proto"
)

func get_randomness() ([]byte, []byte) {
	reveal_bytes := make([]byte, 32)
	n, _ := rand.Read(reveal_bytes)
	if n != len(reveal_bytes) {
		fmt.Fprintf(os.Stderr, "Could not obtain random bytes.\n")
		os.Exit(1)
	}

	commit_bytes := sha256.Sum256(reveal_bytes)
	
	return commit_bytes[:], reveal_bytes
}


func main() {
	public_key, secret_key, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key.\n")
		os.Exit(1)
	}

	commit, _ := get_randomness()

	fingerprint := sha256.Sum256([]byte{})


	verifier_object := protobufs.VerifierCommit{
		public_key,
		"127.0.0.1:1234",
		time.Now().Format(time.RFC3339),
		commit,
		fingerprint[:]}
	verifier_object_json, err := proto.Marshal(&verifier_object)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		os.Exit(1)
	}

	signature := ed25519.Sign(secret_key, verifier_object_json)
	signed_commitment := protobufs.SignedMessage{
		[]byte(public_key), signature, verifier_object_json}
	commitment_encoded, err := proto.Marshal(&signed_commitment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		os.Exit(1)
	}
	os.Stdout.Write(commitment_encoded)
}
