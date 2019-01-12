package otlog

//StorageEngine helps save or get records from various sources
type StorageEngine interface {
	Get(entry *Entry, ref string) (*Entry, error)
	Save(entry *Entry) (string, error)
}
