package secure

import (
	"./crypt"
	"net/http"
	"strconv"
)

type Client struct {
	crypt.Decryptor
	c *http.Client
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("secure-type", c.Type())
	req.Header.Add("secure-publickey", c.PublicKey())
	req.Header.Add("secure-messagesize", strconv.Itoa(c.MessageSize()))
	resp, e := c.c.Do(req)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode < 400 {
		resp.Body = c.NewReader(resp.Body)
	}
	return resp, nil
}

func NewClient(typ, privateKey string) *Client {
	return &Client{crypt.NewDecryptor(typ, privateKey), &http.Client{}}
}
