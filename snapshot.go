package otlog

import (
	"crypto/x509"
	"errors"
)

//Snapshot provides a struct to create snapshots or a record set
type Snapshot struct {
	PubKey  x509.Certificate `json:"pk"`
	Sign    string           `json:"s"`
	Records string           `json:"records"`
}

//GetRecords returns the records stored within the snapshot
func (s *Snapshot) GetRecords(creds CredStore) (*[]interface{}, error) {
	/*
		# Validate snapshot
		# Decrypt
		# Return record set
	*/

	return nil, errors.New("not implmented yet")
}

//NewSnapshot takes in records and saves to storage
func NewSnapshot(creds CredStore, records *[]interface{}, storage StorageEngine) (*Link, error) {
	/*
		# Convert records to json
		# Encrypt records (split?)
		# Create signature
		# Attach pub key
		# Save to storage
		# Return reference
	*/
	return nil, errors.New("not implemented yet")
}

//RecoverSnapshot gets the snapshot from storage
func RecoverSnapshot(ref string, storage StorageEngine) (*Snapshot, error) {
	/*
		# Recover parts
		# Merge data if split
		# Validate snapshot on pub key / sig
		# Return snapshot
	*/

	return nil, errors.New("not implemented yet")
}
