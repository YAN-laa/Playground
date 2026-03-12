package pipeline

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

func parseTime(value string) time.Time {
	if value == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Now().UTC()
	}
	return t.UTC()
}

func fingerprint(tenantID string, eventTime time.Time, aggregationWindow time.Duration, event shared.SuricataEvent) string {
	bucket := eventTime.UTC()
	if aggregationWindow > 0 {
		bucket = bucket.Truncate(aggregationWindow)
	}
	appProto := strings.ToLower(strings.TrimSpace(event.AppProto))
	if appProto == "" {
		appProto = strings.ToLower(strings.TrimSpace(event.Proto))
	}
	raw := strings.Join([]string{
		tenantID,
		bucket.Format(time.RFC3339),
		event.SrcIP,
		event.DstIP,
		fmt.Sprintf("%d", event.DstPort),
		strings.ToLower(strings.TrimSpace(event.Proto)),
		appProto,
		fmt.Sprintf("%d", event.Alert.SignatureID),
	}, "|")
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func riskScore(severity int) int {
	switch severity {
	case 1:
		return 90
	case 2:
		return 75
	case 3:
		return 60
	default:
		return 40
	}
}
