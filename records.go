package otlog

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

//Records holds a set of records
type Records struct {
	store     StorageEngine
	log       *Entry
	credStore CredStore

	Records []Record `json:"records"`
}

//Snapshot saves the records to storage
func (r *Records) Snapshot(creds CredStore) (string, error) {
	return "", errors.New("not implemented yet")
}

//Record ~indivudualrecords
type Record struct {
	ID  uuid.UUID       `json:"_id"`
	Raw json.RawMessage `json:"d"`
}
