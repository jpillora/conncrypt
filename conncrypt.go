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

var salt = []byte("conncrypt")

const DefaultIterations = 2048
const DefaultKeySize = 32 //256bits
var DefaultHashFunc = sha256.New

type Config struct {
	Password   string
	Salt       []byte
	Iterations int
	KeySize    int
	HashFunc   func() hash.Hash
}

func New(conn net.Conn, c *Config) net.Conn {
	//set defaults
	if len(c.Salt) == 0 {
		c.Salt = salt
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
		Conn:   conn,
		reader: reader,
		writer: writer,
	}, nil
}

type cryptoConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c *cryptoConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *cryptoConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}
