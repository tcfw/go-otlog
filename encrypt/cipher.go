package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"time"
)

//Enc encrypts data using AES-256-GCM with TS as nonce+adata
func Enc(data *[]byte, ts time.Time, pk string) (*[]byte, error) {
	hasher := sha512.New()
	hasher.Write([]byte(ts.Format(time.RFC3339)))
	out := hex.EncodeToString(hasher.Sum(nil))
	nonce, _ := hex.DecodeString(out[64:(64 + 24)])
	aData, _ := hex.DecodeString(out)
	k, _ := hex.DecodeString(pk)
	if len(k) < 32 {
		return nil, errors.New("key length too short")
	}
	k = k[:32]

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherText := aesgcm.Seal(nil, nonce, *data, aData)
	return &cipherText, nil
}

//Dec decrypts data using AES-256-GCM with a TS as nonce+adata
func Dec(data *[]byte, ts time.Time, pk string) (*[]byte, error) {
	hasher := sha512.New()
	hasher.Write([]byte(ts.Format(time.RFC3339)))
	out := hex.EncodeToString(hasher.Sum(nil))
	nonce, _ := hex.DecodeString(out[64:(64 + 24)])
	aData, _ := hex.DecodeString(out)
	k, _ := hex.DecodeString(pk)
	if len(k) < 32 {
		return nil, errors.New("key length too short")
	}
	k = k[:32]

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	output, err := aesgcm.Open(nil, nonce, *data, aData)
	if err != nil {
		return nil, err
	}

	return &output, nil
}
