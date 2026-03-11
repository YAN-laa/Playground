package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/yan/ndr-platform/internal/server/httpapi"
	"github.com/yan/ndr-platform/internal/server/search"
	"github.com/yan/ndr-platform/internal/server/service"
	"github.com/yan/ndr-platform/internal/server/store"
)

func NewHandler() (http.Handler, func(), error) {
	repo, cleanup, err := newRepository()
	if err != nil {
		return nil, nil, err
	}
	engine, indexer, err := newSearchComponents(repo)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if initializer, ok := engine.(search.Initializer); ok {
		if err := initializer.EnsureReady(context.Background()); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	svc := service.New(repo, engine, indexer, slowQueryThreshold(), exportDir(), exportTTL(), exportCleanupInterval(), authConfig())
	router := httpapi.New(svc)
	return router.Handler(), cleanup, nil
}

func newRepository() (store.Repository, func(), error) {
	backend := os.Getenv("APP_STORE")
	switch backend {
	case "", "memory":
		return store.NewMemoryStore(), func() {}, nil
	case "postgres":
		databaseURL := os.Getenv("DATABASE_URL")
		if databaseURL == "" {
			return nil, nil, fmt.Errorf("DATABASE_URL is required when APP_STORE=postgres")
		}
		pgStore, err := store.NewPostgresStore(context.Background(), databaseURL)
		if err != nil {
			return nil, nil, err
		}
		return pgStore, pgStore.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported APP_STORE: %s", backend)
	}
}

func newSearchComponents(repo store.Repository) (search.Engine, search.Indexer, error) {
	backend := os.Getenv("APP_SEARCH")
	switch backend {
	case "", "local":
		return search.NewLocalEngine(repo), search.NoopIndexer{}, nil
	case "opensearch":
		baseURL := os.Getenv("OPENSEARCH_URL")
		if baseURL == "" {
			return nil, nil, fmt.Errorf("OPENSEARCH_URL is required when APP_SEARCH=opensearch")
		}
		engine := search.NewOpenSearchEngine(search.OpenSearchConfig{
			BaseURL:      baseURL,
			Username:     os.Getenv("OPENSEARCH_USERNAME"),
			Password:     os.Getenv("OPENSEARCH_PASSWORD"),
			AlertIndex:   os.Getenv("OPENSEARCH_ALERT_INDEX"),
			FlowIndex:    os.Getenv("OPENSEARCH_FLOW_INDEX"),
			Timeout:      5 * time.Second,
			RetryMax:     intEnv("OPENSEARCH_RETRY_MAX", 2),
			RetryBackoff: durationEnv("OPENSEARCH_RETRY_BACKOFF", 500*time.Millisecond),
			DLQFile:      os.Getenv("OPENSEARCH_DLQ_FILE"),
		})
		return engine, engine, nil
	default:
		return nil, nil, fmt.Errorf("unsupported APP_SEARCH: %s", backend)
	}
}

func authConfig() service.AuthConfig {
	return service.AuthConfig{
		Mode:      os.Getenv("APP_AUTH_MODE"),
		JWTSecret: os.Getenv("APP_JWT_SECRET"),
		JWTTTL:    durationEnv("APP_JWT_TTL", 12*time.Hour),
	}
}

func slowQueryThreshold() time.Duration {
	return durationEnv("APP_SLOW_QUERY_THRESHOLD", 1500*time.Millisecond)
}

func exportDir() string {
	if value := os.Getenv("APP_EXPORT_DIR"); value != "" {
		return value
	}
	return "exports"
}

func exportTTL() time.Duration {
	return durationEnv("APP_EXPORT_TTL", 24*time.Hour)
}

func exportCleanupInterval() time.Duration {
	return durationEnv("APP_EXPORT_CLEANUP_INTERVAL", time.Hour)
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func intEnv(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		return fallback
	}
	return value
}
