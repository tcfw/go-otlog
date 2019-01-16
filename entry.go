package otlog

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	encrypt "github.com/tcfw/go-otlog/encrypt"
)

//Operation The operation transformation being applied (e.g. update/delete)
type Operation string

const (
	//OpUpSert the upsert (insert/update) operation
	OpUpSert Operation = "ups"

	//OpDel the delete operation
	OpDel Operation = "del"

	//OpMerge allows for merge operations between other logs
	OpMerge Operation = "merg"

	//OpBase used only for root nodes
	OpBase Operation = "base"
)

//Link provies DAG links/Merkle leaf nodes for IPFS
type Link struct {
	Target string `json:"/"`
}

//Entry holds the DAG struct to go to IPFS
type Entry struct {
	credStore   CredStore
	dataStore   StorageEngine
	isEncrypted bool

	Time       time.Time `json:"t"`
	ID         uuid.UUID `json:"id"`
	CrytpoAlg  string    `json:"c"`
	PublicCert string    `json:"pk"`
	Signature  string    `json:"s"`
	Snapshot   *Link     `json:"sn,omitempty"`
	Data       string    `json:"d"`
	Operation  Operation `json:"o"`
	Parent     []*Link   `json:"p,omitempty"`
}

//NewEntry creates a new entry with populated properties
func NewEntry(parent *Link, credStore CredStore, dataStore StorageEngine) (*Entry, error) {
	if credStore.getPass() == "" {
		return nil, errors.New("CredStore must be set with a password")
	}

	return &Entry{
		credStore: credStore,
		dataStore: dataStore,
		Time:      time.Now().Round(0),
		ID:        uuid.New(),
		CrytpoAlg: encrypt.AlgoAES256SHA256,
		Parent:    []*Link{parent},
		Operation: OpUpSert,
	}, nil
}

//NewEntryFromStorage gets an entry via storage ref
func NewEntryFromStorage(storage StorageEngine, credStore CredStore, head string) (*Entry, error) {
	entry := &Entry{credStore: credStore, dataStore: storage, isEncrypted: true}
	entry, err := storage.Get(entry, head)
	if err != nil {
		return nil, err
	}

	err = entry.DecryptData()
	if err != nil {
		return nil, err
	}

	return entry, nil
}

//Parents provides a map the entries parent(s) ~ multiple for merges
func (e *Entry) Parents() (map[string]*Entry, error) {
	parents := map[string]*Entry{}
	if e.Parent != nil && len(e.Parent) > 0 {
		for _, parent := range e.Parent {
			if parent != nil {
				entry, err := NewEntryFromStorage(e.dataStore, e.credStore, parent.Target)
				if err != nil {
					return nil, err
				}
				parents[parent.Target] = entry
			}
		}
	}
	return parents, nil
}

//Encrypt alias for EncryptString
func (e *Entry) Encrypt(data string) error {
	return e.EncryptString(data)
}

//EncryptString encrypts & adds data from string
func (e *Entry) EncryptString(data string) error {
	return e.encryptBytes([]byte(data))
}

//EncryptFromJSON takes in a struct, converts to JSON and then encrypts & adds to the entry
func (e *Entry) EncryptFromJSON(data interface{}) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return e.encryptBytes(bytes)
}

//DecryptData decrypts and validates data
func (e *Entry) DecryptData() error {
	if !e.isEncrypted {
		return nil
	}

	rawBytes, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil {
		return err
	}

	dRaw, err := encrypt.Dec(&rawBytes, e.Time, e.credStore.getPass())
	if err != nil {
		return err
	}

	dataString := string(*dRaw)

	_, err = e.validateSignature(dataString)
	if err != nil {
		return err
	}

	e.Data = dataString
	e.isEncrypted = false

	return nil
}

func (e *Entry) validateSignature(data string) (bool, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.PublicCert)
	if err != nil {
		return false, err
	}

	pubCert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return false, err
	}
	//TODO validate public cert against CA

	pubKey := pubCert.PublicKey.(*rsa.PublicKey)

	err = encrypt.Verify(e.Signature, []byte(data), *pubKey)
	if err != nil {
		return false, err
	}

	return true, nil
}

//DataToString decrypts data (if required) and returns as string
func (e *Entry) DataToString() (string, error) {
	if e.isEncrypted {
		err := e.DecryptData()
		if err != nil {
			return "", err
		}
	}

	return e.Data, nil
}

//DataToStruct attempets to converts data to an expected struct
func (e *Entry) DataToStruct(expected interface{}) (interface{}, error) {
	dataString, err := e.DataToString()
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(dataString), expected)
	if err != nil {
		return nil, err
	}

	return expected, nil
}

func (e *Entry) encryptBytes(data []byte) error {
	raw, err := encrypt.Enc(&data, e.Time, e.credStore.getPass())
	if err != nil {
		return err
	}

	sig, err := encrypt.Sign(data, *e.credStore.getPrivKey())
	if err != nil {
		return err
	}

	e.Signature = *sig
	e.PublicCert, err = e.credStore.getPubcert()
	if err != nil {
		return err
	}
	e.Data = base64.StdEncoding.EncodeToString(*raw)
	e.isEncrypted = true

	return nil
}

//Save adds the entry to storage
func (e *Entry) Save(previous string) (string, error) {
	if len(e.Parent) == 0 && e.Parent[0] != nil && previous != "" {
		e.Parent = []*Link{{Target: previous}}
	}

	if !e.isEncrypted {
		e.Encrypt(e.Data)
	}

	return e.dataStore.Save(e)
}

//Merge merges 2 entry chains into a single chain
func (e *Entry) Merge(sibling *Entry) (*Entry, error) {
	/*
		# Find common base
		# Collate entries between logs into list sorted by time (diff)
		# Walk through changes (priorities delete over upsert)
		# Create snapshot of records
		# Create new entry as merge refing snapshot and both parents
	*/

	eRef, err := e.Save("")
	if err != nil {
		return nil, err
	}
	pRef, err := sibling.Save("")
	if err != nil {
		return nil, err
	}

	_, _, mapping, err := e.findCommonAncestor(sibling)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("%v\nr: %s\nm: %v\n", base, *ref, mapping)

	originalSnapshot, err := RecoverSnapshot(e.Snapshot.Target, e.dataStore)
	if err != nil {
		return nil, err
	}
	records := &Records{}
	err = originalSnapshot.GetRecords(e.credStore, records)
	if err != nil {
		return nil, err
	}

	mergeEntry, err := NewEntry(nil, e.credStore, e.dataStore)
	if err != nil {
		return nil, err
	}

	if mapping == nil {
		//Assume simple 1 depth merge
		//Use ours ~ playforward diff
		//Create new snap

		sibDiff, err := sibling.DataToStruct(&EntryDiff{})
		if err != nil {
			return nil, err
		}
		sibDiffT := sibDiff.(*EntryDiff)

		records.Records, err = e.applyDiff(*sibDiffT, records.Records)
		if err != nil {
			return nil, err
		}
	} else {
		//Multi diff path
	}

	snapshotRef, err := NewSnapshot(e.credStore, records, e.dataStore)
	if err != nil {
		return nil, err
	}

	mergeEntry.Operation = OpMerge
	mergeEntry.Snapshot = snapshotRef
	mergeEntry.Parent = []*Link{&Link{eRef}, &Link{pRef}}

	return mergeEntry, nil
}

func (e *Entry) applyDiff(diff EntryDiff, records []Record) ([]Record, error) {
	switch diff.Op {
	case OpUpSert:
		return append(records, diff.Record), nil
	case OpDel:
		index := -1
		for i, rec := range records {
			if rec.ID == diff.Record.ID {
				index = i
				break
			}
		}
		records[index] = records[len(records)-1]
		return records[:len(records)-1], nil
	}
	return []Record{}, nil
}

type lcaMapping struct {
	ChildrenA map[string]map[string]bool
	ChildrenB map[string]map[string]bool
	Depths    map[string]int
}

func (e *Entry) findCommonAncestor(sibling *Entry) (*Entry, *string, *lcaMapping, error) {
	if len(e.Parent) == 0 {
		return nil, nil, nil, nil
	}

	// Test 1 depth
	eParents, err := e.Parents()
	if err != nil {
		return nil, nil, nil, err
	}
	sParents, err := sibling.Parents()
	if err != nil {
		return nil, nil, nil, err
	}
	for eTarget, eParent := range eParents {
		for sTarget := range sParents {
			if eTarget == sTarget {
				return eParent, &eTarget, nil, nil
			}
		}
	}

	//LCA
	childrenE, depth, err := e.dfs(map[string]map[string]bool{}, map[string]int{}, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	childrenS, depth, err := sibling.dfs(map[string]map[string]bool{}, depth, 0)
	if err != nil {
		return nil, nil, nil, err
	}

	commons := map[string]int{}

	for ref, nodeDepth := range depth {
		_, okE := childrenE[ref]
		_, okS := childrenS[ref]
		if okE && okS {
			commons[ref] = nodeDepth
		}
	}

	var lca string

	curDepth := MAXDEPTH
	for ref, nDepth := range commons {
		if nDepth < curDepth {
			lca = ref
		}
	}

	lcaNode, err := NewEntryFromStorage(e.dataStore, e.credStore, lca)
	if err != nil {
		return nil, nil, nil, err
	}

	return lcaNode, &lca, &lcaMapping{childrenE, childrenS, depth}, nil

}

//MAXDEPTH is the limit of the depth of the search
const MAXDEPTH = 100000

func (e *Entry) dfs(dfsMap map[string]map[string]bool, depth map[string]int, curDepth int) (map[string]map[string]bool, map[string]int, error) {
	ref, _ := e.Save("")
	parents, err := e.Parents()
	if err != nil {
		return nil, nil, err
	}

	curDepth++
	if curDepth > MAXDEPTH {
		return dfsMap, depth, nil
	}

	for pRef, parent := range parents {
		dfsMap, depth, err = parent.dfs(dfsMap, depth, curDepth)
		if err != nil {
			return nil, nil, err
		}

		if _, ok := dfsMap[pRef]; !ok {
			dfsMap[pRef] = map[string]bool{}
		}
		dfsMap[pRef][ref] = true
		if refDef, ok := depth[pRef]; !ok || curDepth > refDef {
			depth[pRef] = curDepth
		}
	}
	return dfsMap, depth, nil
}
