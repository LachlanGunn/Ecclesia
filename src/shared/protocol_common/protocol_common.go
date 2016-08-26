package protocol_common

import (
	"errors"
	"fmt"
	"encoding/base64"

	"golang.org/x/crypto/ed25519"
	"github.com/golang/protobuf/proto"

	"protobufs"
)

type InvalidPublicKeyError struct {
	Length int
}

func (k *InvalidPublicKeyError) Error() string {
	return fmt.Sprintf("Incorrect public key length: %d (expected %d)",
		k.Length, ed25519.PublicKeySize)
}

type UntrustedPublicKeyError struct {
	Key ed25519.PublicKey
}

func (k *UntrustedPublicKeyError) Error() string {
	return fmt.Sprintf("Untrusted public key: %s",
		base64.StdEncoding.EncodeToString(k.Key))
}

func UnpackSignedData(
	signed_data []byte, validate_public_key func(ed25519.PublicKey) bool ) (
	*protobufs.SignedMessage, error) {

	var signed_message protobufs.SignedMessage
	err := proto.Unmarshal(signed_data, &signed_message)
	if err != nil {
		return nil, err
	}

	if len(signed_message.PublicKey) != ed25519.PublicKeySize {
		return nil, &InvalidPublicKeyError{len(signed_message.PublicKey)}
	}

	public_key := ed25519.PublicKey(signed_message.PublicKey)
	if !validate_public_key(public_key) {
		return nil, errors.New("unacceptable public key")
	}

	if len(signed_message.Signature) != ed25519.SignatureSize {
		return nil, errors.New("incorrect signature length")
	}

	verification_result := ed25519.Verify(
		public_key, signed_message.Data, signed_message.Signature)
	if !verification_result {
		return nil, errors.New("signature validation failed")
	}

	return &signed_message, nil
}
