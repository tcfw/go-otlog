package otlog

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

//CredStore stores RSA/encryption keys
type CredStore struct {
	pass    string
	privKey rsa.PrivateKey
	pubCert x509.Certificate
}

//NewCredStore constructors of basic cred store
func NewCredStore(pass string, privKey rsa.PrivateKey, pubCert x509.Certificate) (*CredStore, error) {
	if pubCert.PublicKey.(*rsa.PublicKey).N.Cmp(privKey.PublicKey.N) != 0 || privKey.PublicKey.E != pubCert.PublicKey.(*rsa.PublicKey).E {
		return nil, errors.New("Given public certificate does not match given private key")
	}

	return &CredStore{
		pass:    pass,
		privKey: privKey,
		pubCert: pubCert,
	}, nil
}

func (e *CredStore) getPass() string {
	return e.pass
}

func (e *CredStore) getPrivKey() *rsa.PrivateKey {
	return &e.privKey
}

func (e *CredStore) getPubcert() (string, error) {
	return base64.StdEncoding.EncodeToString(e.pubCert.Raw), nil
}
