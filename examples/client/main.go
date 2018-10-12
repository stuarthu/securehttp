package main

import (
	"encoding/pem"
	"fmt"
	"github.com/stuarthu/securehttp"
	"io"
	"net/http"
	"os"
)

func main() {
	key := decodeRSAPrivateKeyFromFile(os.Args[1])
	d, e := securehttp.NewDecryptor(securehttp.TypeRSA, key)
	if e != nil {
		panic(e)
	}
	c := &securehttp.Client{d, &http.Client{}}
	resp, e := c.Get("http://localhost:8000")
	if e != nil {
		panic(e)
	}
	if resp.StatusCode != 200 {
		fmt.Println(resp.StatusCode)
	}
	io.Copy(os.Stdout, resp.Body)
}

func decodeRSAPrivateKeyFromFile(file string) string {
	f, e := os.Open(file)
	if e != nil {
		panic(e)
	}
	b := make([]byte, 5000)
	io.ReadFull(f, b)
	block, _ := pem.Decode(b)
	if block == nil {
		panic(e)
	}
	return string(block.Bytes)
}
