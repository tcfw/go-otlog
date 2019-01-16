package otlog

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"

	encrypt "github.com/tcfw/go-otlog/encrypt"
)

//Snapshot provides a struct to create snapshots or a record set
type Snapshot struct {
	PubCert   string    `json:"pk"`
	Signature string    `json:"s"`
	Time      time.Time `json:"t"`
	Records   string    `json:"records"`
}

//GetRecords returns the records stored within the snapshot
func (s *Snapshot) GetRecords(creds CredStore, recordSet interface{}) error {

	// encrypt.ValidatePub(snapshot.PubKey, root)
	rawBytes, err := base64.StdEncoding.DecodeString(s.Records)
	if err != nil {
		return err
	}
	unencRaw, err := encrypt.Dec(&rawBytes, s.Time, creds.getPass())
	if err != nil {
		return err
	}
	valid, err := s.ValidateSignature(unencRaw)
	if err != nil || valid == false {
		return err
	}

	err = json.Unmarshal(*unencRaw, recordSet)
	if err != nil {
		return err
	}

	return nil
}

//ValidateSignature uses the pub cert attached to the
func (s *Snapshot) ValidateSignature(data *[]byte) (bool, error) {
	decoded, err := base64.StdEncoding.DecodeString(s.PubCert)
	if err != nil {
		return false, err
	}

	pubCert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return false, err
	}
	//TODO validate public cert against CA

	pubKey := pubCert.PublicKey.(*rsa.PublicKey)
	err = encrypt.Verify(s.Signature, *data, *pubKey)
	if err != nil {
		return false, err
	}

	return true, nil
}

//NewSnapshot takes in records and saves to storage
func NewSnapshot(creds CredStore, records interface{}, storage StorageEngine) (*Link, error) {
	//TODO Split records into shards

	recordBytes, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}

	t := time.Now().Round(0)

	encBytes, err := encrypt.Enc(&recordBytes, t, creds.getPass())
	if err != nil {
		return nil, err
	}

	pubCert, err := creds.getPubcert()
	if err != nil {
		return nil, err
	}

	sign, err := encrypt.Sign(recordBytes, *creds.getPrivKey())

	snapshot := &Snapshot{
		PubCert:   pubCert,
		Time:      t,
		Signature: *sign,
		Records:   base64.StdEncoding.EncodeToString(*encBytes),
	}

	ref, err := storage.Save(snapshot)
	if err != nil {
		return nil, err
	}

	return &Link{ref}, nil
}

//RecoverSnapshot gets the snapshot from storage
func RecoverSnapshot(ref string, storage StorageEngine) (*Snapshot, error) {
	//TODO recover shards

	return storage.GetSnapshot(ref)
}
