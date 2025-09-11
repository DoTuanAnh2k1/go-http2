package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	h2s := http2.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, HTTP/2!\n"))
	})
	server := &http.Server{
		Addr:    ":1234",
		Handler: h2c.NewHandler(mux, &h2s),
	}

	fmt.Println("Starting server on :1234")
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
