package otlog

//StorageEngine helps save or get records from various sources
type StorageEngine interface {

	//Get an entry
	Get(entry *Entry, ref string) (*Entry, error)

	//Save data arbitrary data
	Save(data interface{}) (string, error)

	//Get a snapshot, allows for separate snapshot storage location if required
	GetSnapshot(ref string) (*Snapshot, error)
}
