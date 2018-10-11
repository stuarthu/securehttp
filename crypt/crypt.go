package crypt

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
	NewReader(io.ReadCloser) io.ReadCloser
}

func NewEncryptedResponseWriter(typ, publicKey string, size int, w http.ResponseWriter) (http.ResponseWriter, error) {
	switch typ {
	case TypeNocrypt:
		return NewNocryptWriter(publicKey, size, w)
	case TypeRSA:
		return NewRSAWriter(publicKey, size, w)
	default:
		return nil, ErrUnknownCrypt
	}
}

func NewDecryptor(typ, privateKey string) Decryptor {
	switch typ {
	case TypeNocrypt:
		return NewNocrypt(privateKey)
	case TypeRSA:
		return NewRSA(privateKey)
	default:
		panic("unknown decryptor " + typ)
	}
}
