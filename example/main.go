package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jpillora/conncrypt"
)

func main() {
	go server()
	time.Sleep(100 * time.Millisecond)
	client()
	time.Sleep(100 * time.Millisecond)
}

func server() {
	l, err := net.Listen("tcp", ":3000")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		conn = conncrypt.New(conn, &conncrypt.Config{
			Password: "my-super-secret-password",
		})

		buff := make([]byte, 0xff)
		for {
			n, err := conn.Read(buff)
			if err != nil {
				log.Println(err)
				break
			}
			fmt.Printf("server: #%dB: %s", n, buff[:n])
		}
	}
}

func client() {
	conn, err := net.Dial("tcp", "127.0.0.1:3000")
	if err != nil {
		log.Fatal(err)
	}
	conn = conncrypt.New(conn, &conncrypt.Config{
		Password: "my-super-secret-password",
	})
	conn.Write([]byte("hello world\n"))
}
