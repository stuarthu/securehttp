package main

import (
	"../../../secureserver"
	"log"
	"net/http"
)

func main() {
	log.Fatal(http.ListenAndServe(":8000", secure.Server(http.FileServer(http.Dir("/tmp")))))
}
