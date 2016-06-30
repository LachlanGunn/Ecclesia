package randomset

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

//
// Package for generating a random subset using a seed value.
//

func RandomSubset(seed []byte, id []byte, n int, k int) ([]int, error) {

	if n < k {
		return nil, errors.New("Not enough choices to select from")
	}
	
	hashed_seed  := sha256.Sum256(seed)
	hashed_id    := sha256.Sum256(id)
	aes_ctx, err := aes.NewCipher(hashed_seed[:])
	if err != nil {
		return nil, err
	}

	ctr := cipher.NewCTR(aes_ctx, hashed_id[0:aes.BlockSize])

	// We use 64-bits of each block
	zero_bytes   := make([]byte, 8)

	result := make([]int, k)
	for i := 0; i < k; {
		random_bytes := make([]byte, 8)
		ctr.XORKeyStream(random_bytes, zero_bytes)

		// There is a slight bias towards the lower values
		// unless the number of verifiers is a power of two.
		// We fix this by excluding the biased values.
		value, _ := binary.Uvarint(random_bytes)
		if value + uint64(n) < value {
			continue
		}
		
		choice := value % uint64(n)
		exists := func() bool {
			for j := 0; j < i; j++ {
				if uint64(result[j]) == choice {
					return true
				}
			}
			return false
		}()
		if !exists {
			result[i] = int(choice)
			i++
		}
	}

	return result, nil
}
