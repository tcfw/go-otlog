package encrypt

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
)

//ValidatePub checks that the passed public cert is part of a given CA
func ValidatePub(pub string, root string) (bool, error) {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(root))
	if !ok {
		return false, errors.New("Failed to parse root certificate")
	}

	pubRaw, _ := hex.DecodeString(pub)
	cert, err := x509.ParseCertificate(pubRaw)
	if err != nil {
		return false, err
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	return err == nil, err
}
