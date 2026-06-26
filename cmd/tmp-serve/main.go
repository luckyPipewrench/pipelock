// Throwaway static file server for the WASM verify proof. Serves a directory on
// 0.0.0.0 with correct MIME types (Go knows .wasm). Delete after use.
package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	dir, addr := os.Args[1], os.Args[2]
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.FileServer(http.Dir(dir)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("serving %s on %s", dir, addr)
	log.Fatal(srv.ListenAndServe())
}
