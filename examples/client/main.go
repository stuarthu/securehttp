package main

import (
	"../../../secureserver"
	"../../crypt"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	req, e := http.NewRequest("GET", "http://localhost:8000", nil)
	if e != nil {
		panic(e)
	}
	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	key := string(x509.MarshalPKCS1PrivateKey(private))
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
