package main

import (
	"encoding/pem"
	"fmt"
	"github.com/stuarthu/secureserver"
	"github.com/stuarthu/secureserver/crypt"
	"io"
	"net/http"
	"os"
)

func main() {
	req, e := http.NewRequest("GET", "http://localhost:8000", nil)
	if e != nil {
		panic(e)
	}
	key := decodeRSAPrivateKeyFromFile(os.Args[1])
	c := secure.NewClient(crypt.TypeRSA, key)
	resp, e := c.Do(req)
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
