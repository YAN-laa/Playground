GOCACHE := $(CURDIR)/.cache/go-build

.PHONY: run-server run-server-pg run-server-os run-probe test build

run-server:
	GOCACHE=$(GOCACHE) go run ./cmd/server

run-server-pg:
	GOCACHE=$(GOCACHE) APP_STORE=postgres DATABASE_URL=postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable go run ./cmd/server

run-server-os:
	GOCACHE=$(GOCACHE) APP_SEARCH=opensearch OPENSEARCH_URL=http://localhost:9200 go run ./cmd/server

run-probe:
	GOCACHE=$(GOCACHE) go run ./cmd/probe-agent

test:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) go test ./...

build:
	mkdir -p $(GOCACHE) bin
	GOCACHE=$(GOCACHE) go build -o bin/ndr-server ./cmd/server
	GOCACHE=$(GOCACHE) go build -o bin/probe-agent ./cmd/probe-agent
