package main

import (
	"log"
	"net/http"
	"os"

	ndrserver "github.com/yan/ndr-platform/internal/server"
)

func main() {
	addr := os.Getenv("NDR_SERVER_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	handler, cleanup, err := ndrserver.NewHandler()
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	log.Printf("ndr server listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
