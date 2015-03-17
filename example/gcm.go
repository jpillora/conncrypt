package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

func main() {

	//generate key
	key := pbkdf2.Key([]byte("foo"), []byte("bar"), 2048, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aead, err := cipher.NewGCM(block)

	fmt.Println(aead.NonceSize())
	fmt.Println(aead.Overhead())

	nonce := []byte("1234567890ab")

	ctext := aead.Seal(nil, nonce, []byte("hello world"), nil)

	fmt.Printf("%d\n", len(ctext))
	fmt.Printf("%s\n", ctext)

	// ctext[5] = 128

	ptext, err := aead.Open(nil, nonce, ctext, nil)
	if err != nil {
		fmt.Printf("err %s\n", err)
	}

	fmt.Printf("%d\n", len(ptext))
	fmt.Printf("%s\n", ptext)
}
