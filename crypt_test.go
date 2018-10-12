package securehttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"testing"
)

type dummy struct {
	buf []byte
}

func (d *dummy) Write(b []byte) (int, error) {
	d.buf = b
	return len(b), nil
}

func (d *dummy) Header() http.Header {
	return nil
}

func (d *dummy) WriteHeader(int) {}

func (d *dummy) Read(b []byte) (int, error) {
	copy(b, d.buf)
	return len(d.buf), nil
}

func (d *dummy) Close() error {
	return nil
}

func TestCrypt(t *testing.T) {
	testCrypt(t, TypeNocrypt, "nokey")

	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	key := string(x509.MarshalPKCS1PrivateKey(private))
	testCrypt(t, TypeRSA, key)

	private, _ = rsa.GenerateKey(rand.Reader, 1024)
	key = string(x509.MarshalPKCS1PrivateKey(private))
	testCrypt(t, TypeRSA, key)

	private, _ = rsa.GenerateKey(rand.Reader, 512)
	key = string(x509.MarshalPKCS1PrivateKey(private))
	testCrypt(t, TypeRSA, key)
}

func testCrypt(t *testing.T, typ, privateKey string) {
	d, e := NewDecryptor(typ, privateKey)
	if e != nil {
		t.Fatal(e)
	}
	w := &dummy{}
	w2, e := NewEncryptedWriter(d.Type(), d.PublicKey(), d.MessageSize(), w)
	if e != nil {
		t.Fatal(e)
	}
	input := []byte{97, 98}
	w2.Write(input)
	w2.(http.Flusher).Flush()

	r := d.NewDecryptedReader(w)
	b := make([]byte, 5000)
	length, e := r.Read(b)
	if e != nil {
		t.Fatal(e)
	}
	if length != len(input) {
		t.Fatal("read length mismatch")
	}
	for i, c := range input {
		if b[i] != c {
			t.Fatal("read content mismatch")
		}
	}
}
