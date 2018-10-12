# securehttp examples

This is server and client examples for securehttp

## go get securehttp from github

* go get -u github.com/stuarthu/securehttp

## run server example

* go run server/main.go

## generate rsa private key

* openssl genrsa -out /tmp/key

## run client example

* go run client/main.go /tmp/key
