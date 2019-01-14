package otlog

import "errors"

//Records holds a set of records
type Records struct {
	store     StorageEngine
	log       *Entry
	credStore CredStore

	Records []interface{} `json:"records"`
}

//Snapshot saves the records to storage
func (r *Records) Snapshot(creds CredStore) (string, error) {
	return "", errors.New("not implemented yet")
}
