package directory

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"encoding/json"
	"time"
	
	"golang.org/x/crypto/ed25519"

	"relier/randomset"
)

type Certificate struct {
	Time time.Time
	Host string
	FingerprintSHA1   string
	FingerprintSHA256 string
}

type signedCertificate struct {
	Certificate []byte
	Signature   []byte
}

type signedDirectory struct {
	Directory []byte
	PublicKey ed25519.PublicKey
	Signature []byte
}

type directoryBody struct {
	Verifiers     []directoryEntry
	LastDirectory string
	Time          time.Time
	Validity      time.Duration
}

type directoryEntry struct {
	Commit          []byte
	Reveal          []byte
	Signature       []byte
}

type verifierCommit struct {
	JSON        []byte
	Signature   []byte
}

type verifierCommitBody struct {
	PublicKey   ed25519.PublicKey
	Address     string
	Time        time.Time
	CommitValue []byte
}

type verifierReveal struct {
	PublicKey   []byte
	RevealValue string
}

type Verifier struct {
	PublicKey ed25519.PublicKey
	Address   string
	Time      time.Time
}

type Directory struct {
	Verifiers   []Verifier
	Time        time.Time
	Validity    time.Duration
	RandomValue []byte
}

func ParseCertificate(data []byte, key ed25519.PublicKey) (Certificate,error) {
	var certificate_container signedCertificate
	err := json.Unmarshal(data, &certificate_container)
	if err != nil {
		return Certificate{}, errors.New(
			"Unparseable certificate container")
	}

	signature_valid := ed25519.Verify(
		key,
		certificate_container.Certificate,
		certificate_container.Signature)

	if !signature_valid {
		return Certificate{},errors.New("Invalid certificate signature")
	}

	var certificate Certificate
	err = json.Unmarshal(certificate_container.Certificate, &certificate)
	if err != nil {
		return Certificate{}, errors.New("Invalid certificate body")
	}

	return certificate, nil
}

func (output *Directory) UnmarshalJSON(data []byte) error {
	var directory_container signedDirectory
	err := json.Unmarshal(data, &directory_container)
	if err != nil {
		return errors.New("Unparseable outer container")
	}

	signature_valid := ed25519.Verify(directory_container.PublicKey,
		directory_container.Directory, directory_container.Signature)
	if !signature_valid {
		return errors.New("Invalid directory signature")
	}

	var directory directoryBody
	err = json.Unmarshal(directory_container.Directory, &directory)
	if err != nil {
		return errors.New("Unparseable directory body")
	}

	output.Validity  = directory.Validity
	output.Time      = directory.Time
	output.Verifiers = make([]Verifier, len(directory.Verifiers))

	var verifier_commit_prev verifierCommitBody
	hash_context := sha256.New()
	for index, verifier_json := range directory.Verifiers {
		var verifier_commit verifierCommitBody
		err = json.Unmarshal(verifier_json.Commit, &verifier_commit)
		if err != nil {
			return errors.New("Unparseable verifier")
		}

		signature_valid := ed25519.Verify(verifier_commit.PublicKey,
			verifier_json.Commit, verifier_json.Signature)

		if index > 0 {
			if bytes.Compare(verifier_commit.PublicKey,
				verifier_commit_prev.PublicKey) < 0 {

				return errors.New("Verifiers out of order")
			}
		}

		if !signature_valid {
			return errors.New("Invalid verifier signature")
		}

		hashed_reveal := sha256.Sum256(verifier_json.Reveal)
		if !bytes.Equal(hashed_reveal[:], verifier_commit.CommitValue) {
			return errors.New("Invalid randomness reveal")
		}

		hash_context.Write(verifier_json.Reveal)

		output.Verifiers[index].PublicKey = verifier_commit.PublicKey
		output.Verifiers[index].Address = verifier_commit.Address
		output.Verifiers[index].Time = verifier_commit.Time

		verifier_commit_prev = verifier_commit
	}

	output.RandomValue = hash_context.Sum(nil)

	return nil
}

func (directory *Directory) RandomVerifiers(
	identity string, count int) ([]Verifier, error) {
	verifiers, err := randomset.RandomSubset(
		directory.RandomValue,
		[]byte(identity),
		len(directory.Verifiers),
		count)

	if err != nil {
		return nil, err
	} else {
		result := make([]Verifier, count)
		for i, vi := range verifiers {
			result[i] = directory.Verifiers[vi]
		}
		return result, nil
	}
}
