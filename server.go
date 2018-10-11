package secure

import (
	"./crypt"
	"log"
	"net/http"
	"strconv"
)

type server struct {
	http.Handler
}

func Server(handler http.Handler) http.Handler {
	return &server{handler}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := r.Header.Get("secure-type")
	if t == "" {
		http.Error(w, "must provide secure-type header", http.StatusUnauthorized)
		return
	}
	k := r.Header.Get("secure-publickey")
	if k == "" {
		http.Error(w, "must provide secure-publickey header", http.StatusUnauthorized)
		return
	}
	ms := r.Header.Get("secure-messagesize")
	if ms == "" {
		http.Error(w, "must provide secure-messagesize header", http.StatusUnauthorized)
		return
	}
	size, e := strconv.Atoi(ms)
	if e != nil {
		log.Println(e)
		http.Error(w, "invalid secure-messagesize header", http.StatusBadRequest)
		return
	}
	w2, e := crypt.NewEncryptedResponseWriter(t, k, size, w)
	if e != nil {
		log.Println(e)
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	s.Handler.ServeHTTP(w2, r)
	w2.(http.Flusher).Flush()
	return
}
