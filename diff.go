package otlog

//EntryDiff provides a delta entry for recrods, to be usually stored in Data
type EntryDiff struct {
	Op     Operation `json:"op"`
	Record Record    `json:"d"`
}
