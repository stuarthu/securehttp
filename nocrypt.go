package securehttp

import (
	"io"
	"net/http"
)

type nocryptWriter struct {
	http.ResponseWriter
}

func (w *nocryptWriter) Flush() {
	return
}

func NewNocryptWriter(key string, size int, w http.ResponseWriter) (EncryptedWriter, error) {
	return &nocryptWriter{w}, nil
}

type nocrypt struct{}

var TypeNocrypt = "nocrypt"

func (c *nocrypt) Type() string {
	return TypeNocrypt
}

func (c *nocrypt) PublicKey() string {
	return "nokey"
}

func (c *nocrypt) MessageSize() int {
	return 0
}

func (c *nocrypt) NewDecryptedReader(r io.ReadCloser) io.ReadCloser {
	return r
}

func NewNocrypt(key string) Decryptor {
	return &nocrypt{}
}
