package conncrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"hash"
	"net"

	"golang.org/x/crypto/pbkdf2"
)

//Confg defaults
const DefaultIterations = 2048
const DefaultKeySize = 32 //256bits
var DefaultHashFunc = sha256.New
var DefaultSalt = []byte(`
(;QUHj.BQ?RXzYSO]ifkXp/G!kFmWyXyEV6Nt!d|@bo+N$L9+<d$|g6e26T}
Ao<:>SOd,6acYKY_ec+(x"R";\'4&fTAVu92GVA-wxBptOTM^2,iP5%)wnhW
hwk=]Snsgymt!3gbP2pe=J//}1a?lp9ej=&TB!C_V(cT2?z8wyoL_-13fd[]
`) //salt must be predefined in order to derive the same key

//Config stores the PBKDF2 key generation parameters
type Config struct {
	Password   string
	Salt       []byte
	Iterations int
	KeySize    int
	HashFunc   func() hash.Hash
}

//New creates an AES encrypted net.Conn by generating
//a key using PBKDF2 with the provided configuration
func New(conn net.Conn, c *Config) net.Conn {
	//set defaults
	if len(c.Salt) == 0 {
		c.Salt = DefaultSalt
	}
	if c.Iterations == 0 {
		c.Iterations = DefaultIterations
	}
	if c.KeySize != 16 && c.KeySize != 24 && c.KeySize != 32 {
		c.KeySize = DefaultKeySize
	}
	if c.HashFunc == nil {
		c.HashFunc = DefaultHashFunc
	}

	//generate key
	key := pbkdf2.Key([]byte(c.Password), c.Salt, c.Iterations, c.KeySize, c.HashFunc)

	// could use scrypt, but it's a bit slow...
	// dk, err := scrypt.Key([]byte(c.Password), c.Salt, 16384, 8, 1, 32)

	//key will be always be the correct size so this will never error
	conn, _ = NewFromKey(conn, key)
	return conn
}

//NewFromKey creates an AES encrypted net.Conn using the provided key
func NewFromKey(conn net.Conn, key []byte) (net.Conn, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := DefaultHashFunc().Sum(key)

	// //hash(key) -> read IV
	// riv := DefaultHashFunc().Sum(key)
	// rstream := cipher.NewOFB(block, riv[:aes.BlockSize])
	// reader := &cipher.StreamReader{S: rstream, R: conn}
	// //hash(read IV) -> write IV
	// wiv := DefaultHashFunc().Sum(riv)
	// wstream := cipher.NewOFB(block, wiv[:aes.BlockSize])
	// writer := &cipher.StreamWriter{S: wstream, W: conn}

	return &cryptoConn{
		Conn:  conn,
		aead:  aead,
		nonce: nonce[:aead.NonceSize()],
		temp:  make([]byte, 4*1024),
		buff:  &bytes.Buffer{},
	}, nil
}

type cryptoConn struct {
	net.Conn
	aead        cipher.AEAD
	nonce, temp []byte
	buff        *bytes.Buffer
}

//replace read and write methods
func (c *cryptoConn) Read(p []byte) (int, error) {
	fmt.Printf("read %d\n", len(p))

	// return c.Conn.Read(p)

	n, err := c.Conn.Read(c.temp)
	if err != nil {
		return 0, err
	}

	ptxt, err := c.aead.Open(nil, c.nonce, c.temp[:n], nil)
	if err != nil {
		return 0, err
	}

	return copy(p, ptxt), nil
}

func (c *cryptoConn) Write(p []byte) (int, error) {
	fmt.Printf("write %d\n", len(p))
	// return c.Conn.Write(p)
	n := len(p)
	_, err := c.Conn.Write(c.aead.Seal(nil, c.nonce, p, nil))
	return n, err
}
