package securehttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
)

type rsaWriter struct {
	key *rsa.PublicKey
	http.ResponseWriter
	size  int
	cache []byte
}

func (w *rsaWriter) Write(b []byte) (int, error) {
	w.cache = append(w.cache, b...)
	for len(w.cache) >= w.size {
		e := w.writeData(w.cache[:w.size])
		if e != nil {
			return len(b), e
		}
		w.cache = w.cache[w.size:]
	}
	return len(b), nil
}

func (w *rsaWriter) writeData(data []byte) error {
	b, e := rsa.EncryptPKCS1v15(rand.Reader, w.key, data)
	if e != nil {
		return e
	}
	w.ResponseWriter.Write(b)
	return nil
}

func (w *rsaWriter) Flush() {
	if len(w.cache) == 0 {
		return
	}
	w.writeData(w.cache)
}

func NewRSAWriter(key string, size int, w http.ResponseWriter) (EncryptedWriter, error) {
	b, e := base64.URLEncoding.DecodeString(key)
	if e != nil {
		return nil, e
	}
	publicKey, e := x509.ParsePKCS1PublicKey(b)
	if e != nil {
		return nil, e
	}
	return &rsaWriter{publicKey, w, size, nil}, nil
}

type rsaDecryptor struct {
	key *rsa.PrivateKey
}

var TypeRSA = "rsa"

func (c *rsaDecryptor) Type() string {
	return TypeRSA
}

func (c *rsaDecryptor) PublicKey() string {
	return base64.URLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&c.key.PublicKey))
}

func (c *rsaDecryptor) MessageSize() int {
	return c.key.Size() - 11
}

type rsaReadCloser struct {
	io.ReadCloser
	*rsaDecryptor
	encryptCache []byte
	plainCache   []byte
}

func (r *rsaReadCloser) fillCache() error {
	buffer := make([]byte, 1<<15)
	length, e := r.ReadCloser.Read(buffer)
	if e != nil && e != io.EOF {
		return e
	}
	r.encryptCache = append(r.encryptCache, buffer[:length]...)
	if e == io.EOF && len(r.encryptCache) == 0 {
		return io.EOF
	}
	size := r.key.Size()
	for len(r.encryptCache) >= size {
		b, e := r.decrypt(r.encryptCache[:size])
		if e != nil {
			return e
		}
		r.plainCache = append(r.plainCache, b...)
		r.encryptCache = r.encryptCache[size:]
	}
	if e == io.EOF {
		b, e := r.decrypt(r.encryptCache)
		if e != nil {
			return e
		}
		r.plainCache = append(r.plainCache, b...)
		r.encryptCache = nil
	}
	return nil
}

func (r *rsaReadCloser) decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return rsa.DecryptPKCS1v15(rand.Reader, r.key, data)
}

func (r *rsaReadCloser) Read(b []byte) (int, error) {
	cacheLen := len(r.plainCache)
	for cacheLen == 0 {
		e := r.fillCache()
		if e != nil {
			return 0, e
		}
		cacheLen = len(r.plainCache)
	}
	length := len(b)
	if length > cacheLen {
		length = cacheLen
	}
	copy(b, r.plainCache[:length])
	r.plainCache = r.plainCache[length:]
	return length, nil
}

func (c *rsaDecryptor) NewDecryptedReader(r io.ReadCloser) io.ReadCloser {
	return &rsaReadCloser{r, c, nil, nil}
}

func NewRSA(key string) (Decryptor, error) {
	privateKey, e := x509.ParsePKCS1PrivateKey([]byte(key))
	if e != nil {
		return nil, e
	}
	return &rsaDecryptor{privateKey}, nil
}
