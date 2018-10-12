package main

import (
	"github.com/stuarthu/securehttp"
	"log"
	"net/http"
)

func main() {
	log.Fatal(http.ListenAndServe(":8000", &securehttp.Server{http.FileServer(http.Dir("/tmp"))}))
}
