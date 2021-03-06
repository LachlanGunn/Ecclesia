package registration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"protobufs"
	"shared/protocol_common"

	"github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ed25519"
)

type CommitResult struct {
	Result          string
	Reason          string
	DistributeWait  float64
	RevealWait      float64
	PublicationWait float64
}

type VerifierReveal struct {
	PublicKey   string
	RevealValue string
}

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

func get_directory_fingerprint(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	fingerprint := sha256.Sum256(body)
	return fingerprint[:], nil
}

func Register(directory string, secret_key ed25519.PrivateKey,
	address string, first bool, log *logrus.Logger) error {

	url_base := fmt.Sprintf("http://%s/verifier", directory)

	public_key := secret_key.Public().(ed25519.PublicKey)

	commit, reveal := get_randomness()

	fingerprint, err := get_directory_fingerprint(
		url_base + "/published")
	if err != nil {
		return err
	}

	verifier_object := protobufs.VerifierCommit{
		public_key,
		address,
		time.Now().Format(time.RFC3339),
		commit,
		fingerprint}
	verifier_object_json, err := proto.Marshal(&verifier_object)
	if err != nil {
		return err
	}

	signature := ed25519.Sign(secret_key, verifier_object_json)
	signed_commitment := protobufs.SignedMessage{
		[]byte(public_key), signature, verifier_object_json}
	commitment_encoded, err := proto.Marshal(&signed_commitment)
	if err != nil {
		return err
	}

	response, err := http.Post(url_base+"/commit",
		"application/octet-string",
		bytes.NewReader(commitment_encoded))
	if err != nil {
		return err
	}
	log.Info("Sent commitment")

	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return err
	}

	var result CommitResult
	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return err
	}

	if result.Result != "success" {
		error_string := fmt.Sprintf(
			"Commit failure: %s\n", result.Reason)
		return errors.New(error_string)
	}

	reveal_request := protobufs.VerifierReveal{[]byte(public_key), reveal}
	reveal_request_json, err := proto.Marshal(&reveal_request)
	if err != nil {
		return err
	}

	// Download the committed values.
	time_to_wait_for_distribute :=
		0.5*result.DistributeWait + 0.5*result.RevealWait
	time.Sleep(time.Duration(time_to_wait_for_distribute) * time.Second)
	response, err = http.Get(url_base + "/list")
	if err != nil {
		return err
	}

	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return err
	}

	var registrations protobufs.VerifierCommitList
	err = proto.Unmarshal(body, &registrations)
	if err != nil {
		return err
	}

	our_position := len(registrations.VerifierCommits)
	for i := range registrations.VerifierCommits {
		if registrations.VerifierCommits[i] == nil {
			return errors.New("invalid verifier in list")
		}
		if protocol_common.Equal(
			*registrations.VerifierCommits[i],
			signed_commitment) {

			our_position = i
			break
		}
	}

	if our_position == len(registrations.VerifierCommits) {
		return errors.New("Commit did not appear in published list.")
	}

	our_published_commit := registrations.VerifierCommits[our_position]

	err = protocol_common.VerifySignedData(
		*our_published_commit,
		func(k ed25519.PublicKey) bool { return true })
	if err != nil {
		return errors.New("Published commit did not validate.")
	}

	// Reveal the committed value
	time.Sleep(time.Duration(
		result.RevealWait-result.DistributeWait) * time.Second)

	response, err = http.PostForm(url_base+"/reveal",
		url.Values{"verifier_data": {string(reveal_request_json)}})
	log.Info("Revealed committed value")

	if err != nil {
		return err
	}

	body, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return err
	}

	return nil
}
