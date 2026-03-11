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

func fingerprint(tenantID, probeID string, event shared.SuricataEvent) string {
	raw := strings.Join([]string{
		tenantID,
		probeID,
		event.SrcIP,
		event.DstIP,
		fmt.Sprintf("%d", event.DstPort),
		event.Proto,
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
