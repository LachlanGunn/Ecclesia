package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ed25519"

	"protobufs"
	"requestor/randomset"
	"shared/protocol_common"
)

type Certificate struct {
	Time              time.Time
	Host              string
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
	Commit    []byte
	Reveal    []byte
	Signature []byte
}

type verifierCommit struct {
	JSON      []byte
	Signature []byte
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

func ParseCertificate(data []byte, key ed25519.PublicKey) (Certificate, error) {
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
		return Certificate{}, errors.New("Invalid certificate signature")
	}

	var certificate Certificate
	err = json.Unmarshal(certificate_container.Certificate, &certificate)
	if err != nil {
		return Certificate{}, errors.New("Invalid certificate body")
	}

	return certificate, nil
}

func ParseDirectory(data []byte) (Directory, error) {
	output := Directory{}

	directory_container, err := protocol_common.UnpackSignedData(
		data, func(ed25519.PublicKey) bool { return true })
	if err != nil {
		return output, errors.New("Invalid directory")
	}

	var directory protobufs.Directory
	err = proto.Unmarshal(directory_container.Data, &directory)
	if err != nil {
		return output, errors.New("Unparseable directory body")
	}

	output.Validity, err = time.ParseDuration(directory.Validity)
	if err != nil {
		return output, errors.New("validity parsing failed")
	}

	output.Time, err = time.Parse(time.RFC3339, directory.Time)
	if err != nil {
		return output, errors.New("time parsing failed")
	}
	output.Verifiers = make([]Verifier, len(directory.DirectoryEntries))

	var verifier_commit_prev protobufs.VerifierCommit
	hash_context := sha256.New()
	for index, directory_entry := range directory.DirectoryEntries {
		if directory_entry.VerifierCommit == nil {
			return output, errors.New("invalid verifier: no commit")
		}
		err = protocol_common.VerifySignedData(
			*directory_entry.VerifierCommit,
			func(key ed25519.PublicKey) bool { return true })
		if err != nil {
			return output, errors.New("invalid verifier")
		}

		if index > 0 {
			if bytes.Compare(directory_entry.VerifierCommit.PublicKey,
				verifier_commit_prev.PublicKey) < 0 {

				return output, errors.New("Verifiers out of order")
			}
		}

		var verifier_commit protobufs.VerifierCommit
		err = proto.Unmarshal(
			directory_entry.VerifierCommit.Data,
			&verifier_commit)
		if err != nil {
			return output, errors.New("invalid verifier")
		}

		hashed_reveal := sha256.Sum256(directory_entry.VerifierReveal)
		if !bytes.Equal(hashed_reveal[:], verifier_commit.CommitValue) {
			return output, errors.New("Invalid randomness reveal")
		}

		hash_context.Write(directory_entry.VerifierReveal)

		output.Verifiers[index].PublicKey =
			directory_entry.VerifierCommit.PublicKey
		output.Verifiers[index].Address = verifier_commit.Address
		output.Verifiers[index].Time, err =
			time.Parse(time.RFC3339, verifier_commit.Time)
		if err != nil {
			return output, errors.New("time parsing failed")
		}

		verifier_commit_prev = verifier_commit
	}

	output.RandomValue = hash_context.Sum(nil)

	return output, nil
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
