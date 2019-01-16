package otlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

//StorageEngine helps save or get records from various sources
type StorageEngine interface {

	//Get an entry
	Get(entry *Entry, ref string) (*Entry, error)

	//Save data arbitrary data
	Save(data interface{}) (string, error)

	//Get a snapshot, allows for separate snapshot storage location if required
	GetSnapshot(ref string) (*Snapshot, error)
}

//MemStore is a testing storage engine to use local memory
type MemStore struct {
	Entries   map[string]*Entry
	Snapshots map[string]*Snapshot
}

//NewMemStore initiates a new mem storage engine
func NewMemStore() *MemStore {
	return &MemStore{
		Entries:   map[string]*Entry{},
		Snapshots: map[string]*Snapshot{},
	}
}

//Get gets entry from direct record ref assuming the entry still has original properties
func (m *MemStore) Get(entry *Entry, ref string) (*Entry, error) {
	rec, ok := m.Entries[ref]
	if !ok {
		return nil, errors.New("Unable to find reference")
	}

	rec.dataStore = m

	return rec, nil
}

//Save calculates a hash of the data then stores to local memory
func (m *MemStore) Save(data interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write(bytes)
	sum := hasher.Sum(nil)
	sumStr := hex.EncodeToString(sum)

	switch ty := data.(type) {
	case *Entry:
		m.Entries[sumStr] = data.(*Entry)
	case *Snapshot:
		m.Snapshots[sumStr] = data.(*Snapshot)
	default:
		return "", fmt.Errorf("Unknown type %s", ty)
	}
	return sumStr, nil
}

//GetSnapshot gets snapshot from direct ref assuming the snapshot still has original properties
func (m *MemStore) GetSnapshot(ref string) (*Snapshot, error) {
	rec, ok := m.Snapshots[ref]
	if !ok {
		return nil, errors.New("Unable to find reference")
	}

	return rec, nil
}
