package encrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

//Sign creates a SHA256 based signature
func Sign(data []byte, pk rsa.PrivateKey) (*string, error) {

	hasher := sha256.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, &pk, crypto.SHA256, sum)
	if err != nil {
		return nil, err
	}

	out := base64.StdEncoding.EncodeToString(sig)
	return &out, nil
}

//Verify verifies a
func Verify(signature string, data []byte, pub rsa.PublicKey) error {

	hasher := sha256.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)

	rawSig, _ := base64.StdEncoding.DecodeString(signature)

	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, sum, rawSig)
}
