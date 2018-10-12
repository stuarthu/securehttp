package securehttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func createServer(isSecure bool) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "test")
	})

	if isSecure {
		return httptest.NewServer(&Server{handler})
	}
	return httptest.NewServer(handler)
}

func testClient(t *testing.T, typ, privateKey string, ts *httptest.Server) {
	d, e := NewDecryptor(typ, privateKey)
	if e != nil {
		t.Fatal(e)
	}
	c := &Client{d, &http.Client{}}
	resp, e := c.Get(ts.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, e := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != "test" {
		t.Fatal(string(b))
	}
}

func testClientsOnServer(t *testing.T, ts *httptest.Server) {
	testClient(t, TypeNocrypt, "nokey", ts)

	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	key := string(x509.MarshalPKCS1PrivateKey(private))
	testClient(t, TypeRSA, key, ts)

	private, _ = rsa.GenerateKey(rand.Reader, 1024)
	key = string(x509.MarshalPKCS1PrivateKey(private))
	testClient(t, TypeRSA, key, ts)

	private, _ = rsa.GenerateKey(rand.Reader, 512)
	key = string(x509.MarshalPKCS1PrivateKey(private))
	testClient(t, TypeRSA, key, ts)
}

func TestClient(t *testing.T) {
	ts := createServer(true)
	defer ts.Close()
	testClientsOnServer(t, ts)

	ts2 := createServer(false)
	defer ts2.Close()
	testClientsOnServer(t, ts2)
}
