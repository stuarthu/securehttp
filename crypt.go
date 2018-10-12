package securehttp

import (
	"errors"
	"io"
	"net/http"
)

var ErrUnknownCrypt = errors.New("Unknown crypt type")

type Decryptor interface {
	Type() string
	PublicKey() string
	MessageSize() int
	NewDecryptedReader(io.ReadCloser) io.ReadCloser
}

type EncryptedWriter interface {
	http.ResponseWriter
	http.Flusher
}

func NewEncryptedWriter(typ, publicKey string, size int, w http.ResponseWriter) (EncryptedWriter, error) {
	switch typ {
	case TypeNocrypt:
		return NewNocryptWriter(publicKey, size, w)
	case TypeRSA:
		return NewRSAWriter(publicKey, size, w)
	default:
		return nil, ErrUnknownCrypt
	}
}

func NewDecryptor(typ, privateKey string) (Decryptor, error) {
	switch typ {
	case TypeNocrypt:
		return NewNocrypt(privateKey), nil
	case TypeRSA:
		return NewRSA(privateKey)
	default:
		return nil, ErrUnknownCrypt
	}
}
