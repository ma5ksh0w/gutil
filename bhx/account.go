package bhx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Account contains name, public key, custom fieldset and signature
type Account struct {
	pub       PubKey
	name      string
	fields    map[string]string
	timestamp uint32
	sign      SigData
}

// PublicKey returns account public key
func (a *Account) PublicKey() *PubKey {
	k := new(PubKey)
	copy(k[:], a.pub[:])
	return k
}

// Name returns account name
func (a *Account) Name() string { return a.name }

// Timestamp returns sign time
func (a *Account) Timestamp() uint32 { return a.timestamp }

// Signature returns account signature
func (a *Account) Signature() *SigData {
	d := new(SigData)
	copy(d[:], a.sign[:])
	return d
}

// Get returns given field value
func (a *Account) Get(name string) string {
	r, _ := a.fields[name]
	return r
}

// IsSet returns true, if given field name is set
func (a *Account) IsSet(name string) bool {
	_, ok := a.fields[name]
	return ok
}

// GetHash returns hash of all account data
func (a *Account) GetHash() Hash256 {
	pubHash := Sha256H(a.pub[:])
	nameHash := Sha256H([]byte(a.name))
	ts := make([]byte, 4)
	PutUint32Le(ts, a.timestamp)
	tsHash := Sha256H(ts)

	fields := make(map[Hash256]Hash256)
	keys := []Hash256{}
	for k, v := range a.fields {
		keyH := Sha256H([]byte(k))
		fields[keyH] = Sha256H([]byte(v))
		keys = append(keys, keyH)
	}

	keys = SortHash256(keys)
	root := Sha256H(pubHash[:], nameHash[:], tsHash[:])

	for _, key := range keys {
		val := fields[key]
		root = Sha256H(key[:], val[:])
	}

	return root
}

// Verify account signature
func (a *Account) Verify() bool {
	hash := a.GetHash()
	return Verify(&a.pub, hash[:], &a.sign)
}

// Bytes returns binary account data
func (a *Account) Bytes() []byte {
	data := make([]byte, 100)
	copy(data[:32], a.pub[:])
	PutUint32Le(data[32:36], a.timestamp)
	copy(data[36:], a.sign[:])

	buf := bytes.NewBuffer(data)
	buf.WriteByte(byte(len(a.name)))
	buf.Write([]byte(a.name))

	for k, v := range a.fields {
		buf.WriteByte(byte(len(k)))
		buf.Write([]byte(k))
		buf.WriteByte(byte(len(v)))
		buf.Write([]byte(v))
	}

	return buf.Bytes()
}

// SetBytes decode raw account
func (a *Account) SetBytes(b []byte) (*Account, error) {
	if len(b) < 100 {
		return nil, fmt.Errorf("invalid data size")
	}

	var (
		pub PubKey
		sig SigData
		err error
		sz  byte
	)

	copy(pub[:], b[:32])
	ts := Uint32Le(b[32:36])
	copy(sig[:], b[36:100])

	r := bytes.NewReader(b[100:])
	sz, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	data := make([]byte, sz)
	if _, err = io.ReadFull(r, data); err != nil {
		return nil, err
	}

	name := string(data)
	fields := make(map[string]string)
	for err == nil {
		sz, err = r.ReadByte()
		if err != nil {
			continue
		}

		data := make([]byte, sz)
		if _, err = io.ReadFull(r, data); err != nil {
			continue
		}

		k := string(data)
		sz, err = r.ReadByte()
		if err != nil {
			continue
		}

		data = make([]byte, sz)
		if _, err = io.ReadFull(r, data); err != nil {
			continue
		}

		fields[k] = string(data)
	}

	a.pub = pub
	a.sign = sig
	a.timestamp = ts
	a.fields = fields
	a.name = name
	return a, nil
}

// ExportJSON returns JSON-encoded account
func (a *Account) ExportJSON() ([]byte, error) {
	return json.Marshal(&struct {
		PublicKey string            `json:"public_key"`
		Name      string            `json:"name"`
		Timestamp uint32            `json:"timestamp"`
		Fields    map[string]string `json:"fields"`
		Signature string            `json:"signature"`
	}{
		Fields:    a.fields,
		Name:      a.name,
		PublicKey: a.pub.String(),
		Signature: a.sign.String(),
		Timestamp: a.timestamp,
	})
}

// ImportJSON decodes account from JSON
func (a *Account) ImportJSON(data []byte) (*Account, error) {
	var tmp struct {
		PublicKey string            `json:"public_key"`
		Name      string            `json:"name"`
		Timestamp uint32            `json:"timestamp"`
		Fields    map[string]string `json:"fields"`
		Signature string            `json:"signature"`
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return nil, err
	}

	a.pub = *(new(PubKey).SetString(tmp.PublicKey))
	a.name = tmp.Name
	a.fields = tmp.Fields
	a.sign = *(new(SigData).SetString(tmp.Signature))
	a.timestamp = tmp.Timestamp
	return a, nil
}

// Keypair used for signing data
type Keypair struct {
	pub  PubKey
	priv PrivKey
}

// NewKeypair generate new keypair
func NewKeypair() (*Keypair, error) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}

	return &Keypair{
		priv: *priv,
		pub:  *pub,
	}, nil
}

// PublicKey returns keypair's public key
func (k *Keypair) PublicKey() *PubKey {
	pub := new(PubKey)
	copy(pub[:], k.pub[:])
	return pub
}

// Sign data
func (k *Keypair) Sign(data []byte) *SigData {
	return Sign(&k.priv, data)
}

// GetAccount create account with keypair's public key
func (k *Keypair) GetAccount(name string, fields map[string]string) *Account {
	a := &Account{
		fields:    fields,
		name:      name,
		timestamp: uint32(time.Now().Unix()),
	}

	copy(a.pub[:], k.pub[:])
	hash := a.GetHash()
	a.sign = *(k.Sign(hash[:]))
	return a
}

// Bytes serialize the keypair
func (k *Keypair) Bytes() []byte {
	return append(k.pub[:], k.priv[:]...)
}

// SetBytes deserialize the keypair
func (k *Keypair) SetBytes(b []byte) (*Keypair, error) {
	if len(b) != 96 {
		return nil, fmt.Errorf("invalid input size")
	}

	var (
		pub  PubKey
		priv PrivKey
	)

	copy(pub[:], b[:32])
	copy(priv[:], b[32:])

	td := make([]byte, 32)
	rand.Read(td)
	sig := Sign(&priv, td)
	if !Verify(&pub, td, sig) {
		return nil, fmt.Errorf("invalid keypair")
	}

	k.priv = priv
	k.pub = pub
	return k, nil
}

// GetEncrypted cipher raw keypair
func (k *Keypair) GetEncrypted(passw string) ([]byte, error) {
	key := Sha256H(Sha256H([]byte(passw)).Bytes())
	block, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, k.Bytes(), nil)
	return append(nonce, ciphertext...), nil
}

// SetEncrypted decrypt ciphered keypair and deserialize it
func (k *Keypair) SetEncrypted(input []byte, passw string) (*Keypair, error) {
	if len(input) < 12 {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	key := Sha256H(Sha256H([]byte(passw)).Bytes())
	block, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 0-12 byte is nonce, 12-... is ciphertext
	data, err := gcm.Open(nil, input[:12], input[12:], nil)
	if err != nil {
		return nil, err
	}

	return k.SetBytes(data)
}

// MyAccount combines the account and the keypair
type MyAccount struct {
	Name   string
	Fields map[string]string
	Keys   *Keypair
}

// MakeNewAccount creates keypair and returns account
func MakeNewAccount(name string) (*MyAccount, error) {
	keys, err := NewKeypair()
	if err != nil {
		return nil, err
	}

	return &MyAccount{
		Fields: make(map[string]string),
		Keys:   keys,
		Name:   name,
	}, nil
}

// GetAccount returns public account for distribution
func (a *MyAccount) GetAccount() *Account {
	return a.Keys.GetAccount(a.Name, a.Fields)
}

// ExportJSON encodes account to JSON with keys encryption
func (a *MyAccount) ExportJSON(passw string) ([]byte, error) {
	enc, err := a.Keys.GetEncrypted(passw)
	if err != nil {
		return nil, err
	}

	return json.Marshal(&struct {
		Name   string            `json:"name"`
		Fields map[string]string `json:"fields"`
		Keys   string            `json:"keys"`
	}{
		Name:   a.Name,
		Fields: a.Fields,
		Keys:   HexEnc(enc),
	})
}

// ImportJSON decodes account and decrypt keys
func (a *MyAccount) ImportJSON(data []byte, passw string) (*MyAccount, error) {
	var tmp struct {
		Name   string            `json:"name"`
		Fields map[string]string `json:"fields"`
		Keys   string            `json:"keys"`
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return nil, err
	}

	keys, err := new(Keypair).SetEncrypted(HexDec(tmp.Keys), passw)
	if err != nil {
		return nil, err
	}

	a.Fields = tmp.Fields
	a.Name = tmp.Name
	a.Keys = keys
	return a, nil
}
