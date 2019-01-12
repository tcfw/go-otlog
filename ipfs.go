package otlog

import (
	"encoding/json"

	shell "github.com/ipfs/go-ipfs-shell"
)

//IpfsStore uses IPFS to save/get entries
type IpfsStore struct {
	Shell *shell.Shell
}

//Get from IPFS as Dag
func (ipfs *IpfsStore) Get(entry *Entry, ref string) (*Entry, error) {
	err := ipfs.Shell.DagGet(ref, entry)
	return entry, err
}

//Save to IPFS as DAG
func (ipfs *IpfsStore) Save(entry *Entry) (string, error) {
	bytes, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}

	return ipfs.Shell.DagPut(bytes, "json", "cbor")
}
