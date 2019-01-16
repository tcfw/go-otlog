package otlog

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"
)

func TestNewSnapshot(t *testing.T) {
	credStore := *generateTestCredStore()
	storage := NewMemStore()
	records := []basicTestRecord{{uuid.Nil, "Test"}}

	ref, err := NewSnapshot(credStore, records, storage)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, ref.Target)
}

func TestRecoverSnapshot(t *testing.T) {
	credStore := *generateTestCredStore()
	storage := NewMemStore()
	records := []basicTestRecord{{uuid.Nil, "Test"}}

	//Create a snapshot to recover
	ref, err := NewSnapshot(credStore, records, storage)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := RecoverSnapshot(ref.Target, storage)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, snapshot.PubCert)
	assert.NotEmpty(t, snapshot.Time)
	assert.NotEmpty(t, snapshot.Signature)
	assert.NotEmpty(t, snapshot.Records)
}
