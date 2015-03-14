package conncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"net"

	"golang.org/x/crypto/pbkdf2"
)

//Confg defaults
const DefaultIterations = 2048
const DefaultKeySize = 32 //256bits
var DefaultHashFunc = sha256.New
var DefaultSalt = []byte("conncrypt")

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
	//key will be always be the correct size so this will never error
	conn, _ = NewFromKey(conn, key)
	return conn
}

//NewFromKey creates an AES encrypted net.Conn using the provided key
func NewFromKey(conn net.Conn, key []byte) (net.Conn, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	//hash(key) -> read IV
	riv := DefaultHashFunc().Sum(key)
	rstream := cipher.NewOFB(block, riv[:aes.BlockSize])
	reader := &cipher.StreamReader{S: rstream, R: conn}
	//hash(read IV) -> write IV
	wiv := DefaultHashFunc().Sum(riv)
	wstream := cipher.NewOFB(block, wiv[:aes.BlockSize])
	writer := &cipher.StreamWriter{S: wstream, W: conn}

	return &cryptoConn{
		Conn: conn,
		r:    reader,
		w:    writer,
	}, nil
}

type cryptoConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

//replace read and write methods
func (c *cryptoConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
func (c *cryptoConn) Write(p []byte) (int, error) {
	return c.w.Write(p)
}
