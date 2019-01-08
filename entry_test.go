package otlog

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"

	ipfsShell "github.com/ipfs/go-ipfs-shell"
	"github.com/stretchr/testify/assert"
)

var TestPass = hex.EncodeToString([]byte(`abcdefhigKLMNOPQRSTUVWXYZ_123456`))

func generateTestKeys() (*rsa.PrivateKey, *x509.Certificate, error) {

	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "test._.example.com.clog.com",
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	cert, _ := x509.ParseCertificate(certBytes)
	return privKey, cert, nil

}

func generateTestCredStore() *CredStore {
	privKey, pubCert, _ := generateTestKeys()
	encryptor, _ := NewCredStore(TestPass, *privKey, *pubCert)

	return encryptor
}

func TestNewEntry(t *testing.T) {
	privKey, pubCert, err := generateTestKeys()
	if err != nil {
		t.Error(err)
	}

	encryptor, err := NewCredStore(TestPass, *privKey, *pubCert)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %s", err.Error())
	}

	_, err = NewEntry(*encryptor, nil)
	if err != nil {
		t.Error(err)
	}

	//Empty CredStore
	encryptor = &CredStore{}
	_, err = NewEntry(*encryptor, nil)
	if err == nil {
		t.Error("Must pick up that no pass exists")
	}
}

func TestEncryptString(t *testing.T) {
	entry, _ := NewEntry(*generateTestCredStore(), nil)

	err := entry.EncryptString("test")
	if err != nil {
		t.Error(err)
	}
	if entry.Data == "test" {
		t.Error("Encrypted data still matches original data")
	}
	if entry.Signature == "" {
		t.Error("Signure failed")
	}
	if entry.PublicCert == "" {
		t.Error("Pub Cert not attached")
	}
}

func TestDecryptString(t *testing.T) {
	origData := `test`

	entry, _ := NewEntry(*generateTestCredStore(), nil)

	err := entry.Encrypt(origData)
	if err != nil {
		t.Error(err)
	}

	err = entry.DecryptData()
	if err != nil {
		t.Error(err)
	}

	//Double decrypt
	err = entry.DecryptData()
	if err != nil {
		t.Error(err)
	}

	if entry.Data != origData {
		t.Error("Original data is lost")
	}
}

func TestInvalidSigs(t *testing.T) {
	origData := `test`

	entry, _ := NewEntry(*generateTestCredStore(), nil)

	invalids := []struct {
		Sig  string
		Desc string
	}{
		{Sig: "2", Desc: "Invalid base64"},
		{Sig: base64.StdEncoding.EncodeToString([]byte("2")), Desc: "Invalid sig"},
	}

	for _, invalid := range invalids {
		t.Run(fmt.Sprintf("Invalid sig: %s", invalid.Desc), func(t *testing.T) {
			err := entry.Encrypt(origData)
			if err != nil {
				t.Fatal(err)
			}

			entry.Signature = invalid.Sig

			_, err = entry.validateSignature(origData)
			if err == nil {
				t.Error("Should have failed")
			}
		})
	}
}

func TestInvalidPubCerts(t *testing.T) {
	origData := `test`
	entry, _ := NewEntry(*generateTestCredStore(), nil)

	invalids := []struct {
		Cert string
		Desc string
	}{
		{Cert: "2", Desc: "Invalid base64"},
		{Cert: base64.StdEncoding.EncodeToString([]byte("2")), Desc: "Invalid cert"},
	}

	for _, invalid := range invalids {
		t.Run(fmt.Sprintf("Invalid sig: %s", invalid.Desc), func(t *testing.T) {
			err := entry.Encrypt(origData)
			if err != nil {
				t.Fatal(err)
			}

			entry.PublicCert = invalid.Cert

			_, err = entry.validateSignature(origData)
			if err == nil {
				t.Error("Should have failed")
			}
		})
	}
}

func TestInvalidEncData(t *testing.T) {
	origData := `test`
	entry, _ := NewEntry(*generateTestCredStore(), nil)

	invalids := []struct {
		Data string
		Desc string
	}{
		{Data: "2", Desc: "Invalid base64"},
		{Data: base64.StdEncoding.EncodeToString([]byte("2")), Desc: "Invalid cert"},
	}

	for _, invalid := range invalids {
		t.Run(fmt.Sprintf("Invalid sig: %s", invalid.Desc), func(t *testing.T) {
			err := entry.Encrypt(origData)
			if err != nil {
				t.Fatal(err)
			}

			entry.Data = invalid.Data
			err = entry.DecryptData()
			if err == nil {
				t.Error("Should have failed")
			}
		})
	}

}

func TestDataToString(t *testing.T) {
	origData := `test`
	entry, _ := NewEntry(*generateTestCredStore(), nil)

	err := entry.EncryptString(origData)
	if err != nil {
		t.Error(err)
	}

	nData, err := entry.DataToString()
	if err != nil {
		t.Error(err)
	}
	if nData != origData {
		t.Error("Original data lost")
	}
}

func TestEncryptStruct(t *testing.T) {
	basicStruct := &struct {
		Name string `json:"name"`
	}{
		Name: "Test",
	}

	entry, _ := NewEntry(*generateTestCredStore(), nil)
	err := entry.EncryptFromJSON(basicStruct)
	if err != nil {
		t.Error(err)
	}

	compStructDef := &struct {
		Name string `json:"name"`
	}{}

	_, err = entry.DataToStruct(compStructDef)
	if err != nil {
		t.Error(err)
	}

	if basicStruct.Name != compStructDef.Name {
		t.Error("Data Comparison failed")
	}

}

func TestIPFSSave(t *testing.T) {
	shell := ipfsShell.NewShell("localhost:5001")
	origData := `test`
	entry, _ := NewEntry(*generateTestCredStore(), nil)

	nTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
	if err != nil {
		t.Error(err)
	}
	entry.Time = nTime
	entry.EncryptString(origData)

	//Remove authenticators otherwise will always result in a different hash
	entry.PublicCert = ""
	entry.Signature = ""

	expectedHead := "zdpuB3arcBMi4j7qwwe1G2XMcoQy3tnc5ZYCRZEXzyxDJnAQ7"

	head, err := entry.Save(shell, "")
	if err != nil {
		t.Error(err)
	}
	if head != expectedHead {
		t.Errorf("Unexpected head, should have been (%s) but got (%s)", expectedHead, head)
	}
}

func TestNewEntryFromIPFS(t *testing.T) {
	encryptor := generateTestCredStore()

	shell := ipfsShell.NewShell("localhost:5001")
	origData := `test`
	entry, _ := NewEntry(*encryptor, nil)
	entry.EncryptString(origData)

	head, _ := entry.Save(shell, "")
	t.Log("Head at ", head, " Data: ", entry.Data)
	entry.DecryptData()

	ipfsEntry, err := NewEntryFromIPFS(shell, *encryptor, head)
	if err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, entry, ipfsEntry)
}
