# conncrypt

Symmetrically encrypt your Go net.Conns

[![GoDoc](https://godoc.org/github.com/jpillora/conncrypt?status.svg)](https://godoc.org/github.com/jpillora/conncrypt)

### Install

```
go get -v github.com/jpillora/conncrypt
```

### Usage

See [example/main.go](example/main.go)

``` go
conn, err := net.Dial("tcp", "127.0.0.1:3000")
if err != nil {
	log.Fatal(err)
}

conn.Write([]byte("hello world\n"))

//encrypt and decrypt conn using with AES256
conn = conncrypt.New(conn, &conncrypt.Config{
	Password: "my-super-secret-password",
})

conn.Write([]byte("hello world\n"))
```

```
hello world
m�o�׫b�7\�⏎
```

#### MIT License

Copyright © 2015 Jaime Pillora &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.