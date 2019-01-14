package otlog

import (
	"github.com/google/uuid"
)

//EntryDiff provides a delta entry for recrods, to be usually stored in Data
type EntryDiff struct {
	Op     Operation   `json:"op"`
	ID     uuid.UUID   `json:"_id,omitempty"`
	Record interface{} `json:"rec"`
}
