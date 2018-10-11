# secureserver examples

This is server and client examples for secureserver

## go get secureserver from github

* go get github.com/stuarthu/secureserver

## run server example

* go run server/main.go

## generate rsa private key

* openssl genrsa -out /tmp/key

## run client example

* go run client/main.go rsa /tmp/key
