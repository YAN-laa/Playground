package server

import (
	"os"
	"testing"
)

func TestPostgresHandlerInit(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set")
	}

	t.Setenv("APP_STORE", "postgres")
	t.Setenv("DATABASE_URL", databaseURL)

	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if handler == nil {
		t.Fatal("expected handler to be initialized")
	}
}
