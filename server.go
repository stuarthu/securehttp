package securehttp

import (
	"log"
	"net/http"
	"strconv"
)

type Server struct {
	http.Handler
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := r.Header.Get("secure-type")
	if t == "" {
		s.Handler.ServeHTTP(w, r)
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
	w2, e := NewEncryptedWriter(t, k, size, w)
	if e != nil {
		log.Println(e)
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	w2.Header().Set("secure-type", t)
	s.Handler.ServeHTTP(w2, r)
	w2.Flush()
	return
}
