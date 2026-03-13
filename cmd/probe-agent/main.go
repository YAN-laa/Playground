package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

type persistedBatch struct {
	FileName string
	Size     int64
	Batch    shared.EventBatch
}

type eveOffsetState struct {
	Path    string    `json:"path"`
	Offset  int64     `json:"offset"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Inode   uint64    `json:"inode"`
}

type eveTracker struct {
	path      string
	stateFile string
	state     eveOffsetState
}

type httpDataOffsetState struct {
	Path    string    `json:"path"`
	Offset  int64     `json:"offset"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Inode   uint64    `json:"inode"`
}

type httpPacketPair struct {
	BaseKey        string
	RequestPacket  string
	ResponsePacket string
	UpdatedAt      time.Time
}

type httpDataTracker struct {
	path      string
	stateFile string
	state     httpDataOffsetState
	packets   map[string]httpPacketPair
}

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "server base url")
	tenantID := flag.String("tenant", "demo-tenant", "tenant id")
	probeCode := flag.String("probe-code", "probe-demo-01", "probe code")
	probeName := flag.String("name", "Demo Probe", "probe name")
	daemonMode := flag.Bool("daemon", false, "run as a long-lived probe agent")
	pollInterval := flag.Duration("poll-interval", 0, "binding poll interval, e.g. 10s")
	pollCount := flag.Int("poll-count", 1, "number of binding polls to perform before exiting, ignored in daemon mode")
	heartbeatInterval := flag.Duration("heartbeat-interval", 15*time.Second, "heartbeat interval in daemon mode")
	maxRuntime := flag.Duration("max-runtime", 0, "optional max runtime in daemon mode")
	eventInterval := flag.Duration("event-interval", 30*time.Second, "event ingest interval in daemon mode")
	bufferDir := flag.String("buffer-dir", "", "directory used to persist failed event batches")
	bufferMaxFiles := flag.Int("buffer-max-files", intEnv("NDR_BUFFER_MAX_FILES", 200), "maximum buffered batch files before oldest files are pruned")
	bufferMaxBytes := flag.Int64("buffer-max-bytes", int64Env("NDR_BUFFER_MAX_BYTES", 64*1024*1024), "maximum buffered bytes before oldest files are pruned")
	eveStateFile := flag.String("eve-state-file", "", "state file used to persist eve.json offsets across restarts")
	httpDataFile := flag.String("http-data-file", "", "path to Suricata http-data.log for raw HTTP packet evidence")
	httpDataStateFile := flag.String("http-data-state-file", "", "state file used to persist http-data.log offsets across restarts")
	flag.Parse()

	queueDir := *bufferDir
	if queueDir == "" {
		if env := os.Getenv("NDR_BUFFER_DIR"); env != "" {
			queueDir = env
		} else {
			queueDir = filepath.Join(".", "probe-buffer")
		}
	}
	if err := os.MkdirAll(queueDir, 0o755); err != nil {
		log.Fatalf("prepare buffer dir failed: %v", err)
	}

	if path := os.Getenv("NDR_EVE_FILE"); path != "" {
		statePath := strings.TrimSpace(*eveStateFile)
		if statePath == "" {
			statePath = strings.TrimSpace(os.Getenv("NDR_EVE_STATE_FILE"))
		}
		if statePath == "" {
			statePath = filepath.Join(queueDir, "eve-offset.json")
		}
		initEVETracker(path, statePath)
	}
	httpDataPath := strings.TrimSpace(*httpDataFile)
	if httpDataPath == "" {
		httpDataPath = strings.TrimSpace(os.Getenv("NDR_HTTP_DATA_FILE"))
	}
	if httpDataPath != "" {
		statePath := strings.TrimSpace(*httpDataStateFile)
		if statePath == "" {
			statePath = strings.TrimSpace(os.Getenv("NDR_HTTP_DATA_STATE_FILE"))
		}
		if statePath == "" {
			statePath = filepath.Join(queueDir, "http-data-offset.json")
		}
		initHTTPDataTracker(httpDataPath, statePath)
	}

	probe := register(*serverURL, shared.RegisterProbeRequest{
		TenantID:    *tenantID,
		ProbeCode:   *probeCode,
		Name:        *probeName,
		Version:     "0.1.0",
		RuleVersion: "suricata-demo",
	})

	heartbeat(*serverURL, shared.HeartbeatRequest{
		TenantID: *tenantID,
		ProbeID:  probe.ID,
		Status:   "online",
		CPUUsage: 12.3,
		MemUsage: 42.0,
		DropRate: 0,
	})

	lastAppliedConfigID := ""
	lastAppliedRuleBundleID := ""
	currentVersion := probe.Version
	if *daemonMode {
		syncBinding(*serverURL, *tenantID, probe.ID, &lastAppliedConfigID, &lastAppliedRuleBundleID)
		syncUpgradeTask(*serverURL, *tenantID, probe.ID, &currentVersion)
	} else {
		for i := 0; i < max(1, *pollCount); i++ {
			syncBinding(*serverURL, *tenantID, probe.ID, &lastAppliedConfigID, &lastAppliedRuleBundleID)
			syncUpgradeTask(*serverURL, *tenantID, probe.ID, &currentVersion)
			if i < max(1, *pollCount)-1 && *pollInterval > 0 {
				time.Sleep(*pollInterval)
			}
		}
	}

	sendEvents(*serverURL, *tenantID, probe.ID, queueDir, *bufferMaxFiles, *bufferMaxBytes)

	log.Printf("demo probe completed: probe_id=%s", probe.ID)
	if !*daemonMode {
		return
	}

	log.Printf("probe daemon started: probe_id=%s heartbeat_interval=%s poll_interval=%s event_interval=%s", probe.ID, heartbeatInterval.String(), pollInterval.String(), eventInterval.String())
	startedAt := time.Now()
	heartbeatTicker := time.NewTicker(*heartbeatInterval)
	defer heartbeatTicker.Stop()
	bindingTicker := time.NewTicker(positiveDuration(*pollInterval, *heartbeatInterval))
	defer bindingTicker.Stop()
	eventTicker := time.NewTicker(*eventInterval)
	defer eventTicker.Stop()
	for {
		select {
		case <-heartbeatTicker.C:
			heartbeat(*serverURL, shared.HeartbeatRequest{
				TenantID: *tenantID,
				ProbeID:  probe.ID,
				Status:   "online",
				CPUUsage: 10.5,
				MemUsage: 41.2,
				DropRate: 0,
			})
		case <-bindingTicker.C:
			syncBinding(*serverURL, *tenantID, probe.ID, &lastAppliedConfigID, &lastAppliedRuleBundleID)
			syncUpgradeTask(*serverURL, *tenantID, probe.ID, &currentVersion)
		case <-eventTicker.C:
			sendEvents(*serverURL, *tenantID, probe.ID, queueDir, *bufferMaxFiles, *bufferMaxBytes)
		}
		if *maxRuntime > 0 && time.Since(startedAt) >= *maxRuntime {
			log.Printf("probe daemon stopped after max-runtime: probe_id=%s", probe.ID)
			return
		}
	}
}

func register(serverURL string, req shared.RegisterProbeRequest) shared.Probe {
	var probe shared.Probe
	must(postJSON(serverURL+"/api/v1/probes/register", req, &probe))
	return probe
}

func heartbeat(serverURL string, req shared.HeartbeatRequest) {
	if err := postJSON(serverURL+"/api/v1/probes/heartbeat", req, nil); err != nil {
		log.Printf("heartbeat failed: probe_id=%s err=%v", req.ProbeID, err)
	}
}

func ingest(serverURL string, req shared.EventBatch) error {
	return postJSON(serverURL+"/api/v1/events/ingest", req, nil)
}

func fetchBinding(serverURL, probeID string) (shared.ProbeBindingDetail, bool) {
	resp, err := http.Get(serverURL + "/api/v1/probes/" + probeID + "/binding")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return shared.ProbeBindingDetail{}, false
	}
	if resp.StatusCode >= 300 {
		log.Fatalf("request failed: %s", resp.Status)
	}
	var detail shared.ProbeBindingDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		log.Fatal(err)
	}
	return detail, true
}

func ackDeployment(serverURL string, req shared.DeploymentAckRequest) {
	if err := postJSON(serverURL+"/api/v1/deployments/ack", req, nil); err != nil {
		log.Printf("deployment ack failed: probe_id=%s err=%v", req.ProbeID, err)
	}
}

func fetchUpgradeTask(serverURL, probeID string) (shared.ProbeUpgradeTask, bool) {
	resp, err := http.Get(serverURL + "/api/v1/probes/" + probeID + "/upgrade-task")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return shared.ProbeUpgradeTask{}, false
	}
	if resp.StatusCode >= 300 {
		log.Fatalf("request failed: %s", resp.Status)
	}
	var task shared.ProbeUpgradeTask
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		log.Fatal(err)
	}
	return task, true
}

func ackUpgradeTask(serverURL string, req shared.ProbeUpgradeAckRequest) {
	if err := postJSON(serverURL+"/api/v1/probe-upgrades/ack", req, nil); err != nil {
		log.Printf("upgrade ack failed: probe_id=%s err=%v", req.ProbeID, err)
	}
}

func sendEvents(serverURL, tenantID, probeID, queueDir string, maxFiles int, maxBytes int64) {
	if err := flushQueuedEvents(serverURL, queueDir); err != nil {
		log.Printf("flush queued events failed: probe_id=%s err=%v", probeID, err)
	}
	events := loadEvents()
	if len(events) == 0 {
		return
	}
	batch := shared.EventBatch{
		TenantID: tenantID,
		ProbeID:  probeID,
		Events:   events,
	}
	if err := ingest(serverURL, batch); err != nil {
		log.Printf("event ingest failed, queueing batch: probe_id=%s events=%d err=%v", probeID, len(events), err)
		if queueErr := enqueueBatch(queueDir, batch, maxFiles, maxBytes); queueErr != nil {
			log.Printf("queue batch failed: probe_id=%s err=%v", probeID, queueErr)
		}
		return
	}
	log.Printf("events ingested: probe_id=%s events=%d alerts=%d", probeID, len(events), countAlertEvents(events))
}

func syncBinding(serverURL, tenantID, probeID string, lastAppliedConfigID, lastAppliedRuleBundleID *string) {
	binding, ok := fetchBinding(serverURL, probeID)
	if !ok {
		return
	}
	if binding.Binding.ProbeConfigID == *lastAppliedConfigID && binding.Binding.RuleBundleID == *lastAppliedRuleBundleID {
		return
	}
	status, message := evaluateBinding(binding)
	ackDeployment(serverURL, shared.DeploymentAckRequest{
		TenantID:      tenantID,
		ProbeID:       probeID,
		ProbeConfigID: binding.Binding.ProbeConfigID,
		RuleBundleID:  binding.Binding.RuleBundleID,
		Status:        status,
		Message:       message,
	})
	if status == "applied" {
		*lastAppliedConfigID = binding.Binding.ProbeConfigID
		*lastAppliedRuleBundleID = binding.Binding.RuleBundleID
	}
	log.Printf("binding sync result: probe_id=%s status=%s config=%s rules=%s", probeID, status, binding.Binding.ProbeConfigID, binding.Binding.RuleBundleID)
}

func syncUpgradeTask(serverURL, tenantID, probeID string, currentVersion *string) {
	task, ok := fetchUpgradeTask(serverURL, probeID)
	if !ok {
		return
	}
	status, message := evaluateUpgradeTask(task, *currentVersion)
	ackUpgradeTask(serverURL, shared.ProbeUpgradeAckRequest{
		TenantID:      tenantID,
		ProbeID:       probeID,
		Action:        task.Action,
		TargetVersion: task.TargetVersion,
		Status:        status,
		Message:       message,
	})
	if status == "applied" {
		*currentVersion = task.TargetVersion
	}
	log.Printf("upgrade sync result: probe_id=%s action=%s target=%s status=%s", probeID, task.Action, task.TargetVersion, status)
}

func evaluateBinding(binding shared.ProbeBindingDetail) (string, string) {
	if os.Getenv("NDR_FORCE_APPLY_FAIL") == "1" {
		return "failed", "forced apply failure"
	}
	if !binding.RuleBundle.Enabled {
		return "failed", "rule bundle is disabled"
	}
	if len(binding.ProbeConfig.OutputTypes) == 0 {
		return "failed", "probe config has no output types"
	}
	return "applied", "probe pulled binding and applied locally"
}

func evaluateUpgradeTask(task shared.ProbeUpgradeTask, currentVersion string) (string, string) {
	if os.Getenv("NDR_FORCE_UPGRADE_FAIL") == "1" {
		return "failed", "forced upgrade failure"
	}
	if strings.TrimSpace(task.TargetVersion) == "" {
		return "failed", "target version is empty"
	}
	if task.TargetVersion == currentVersion {
		return "applied", "target version already active"
	}
	switch task.Action {
	case "rollback":
		return "applied", "probe rolled back to target version"
	default:
		return "applied", "probe upgraded to target version"
	}
}

func postJSON(url string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("request failed: status=%s body=%s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

var eveStateTracker *eveTracker
var httpDataStateTracker *httpDataTracker

func loadEvents() []shared.SuricataEvent {
	var events []shared.SuricataEvent
	if eveStateTracker != nil {
		var err error
		events, err = eveStateTracker.load()
		if err != nil {
			log.Printf("load eve events failed: path=%s err=%v", eveStateTracker.path, err)
			return nil
		}
	} else if path := os.Getenv("NDR_EVE_FILE"); path != "" {
		var err error
		events, err = loadEventsFromEVEFile(path)
		if err != nil {
			log.Printf("load eve events failed: path=%s err=%v", path, err)
			return nil
		}
	} else {
		events = loadDemoEvents()
	}
	if len(events) == 0 {
		return nil
	}
	if httpDataStateTracker != nil {
		if err := httpDataStateTracker.load(); err != nil {
			log.Printf("load http-data packets failed: path=%s err=%v", httpDataStateTracker.path, err)
		} else {
			enrichEventsWithHTTPPackets(events, httpDataStateTracker.packets)
		}
	}
	return events
}

func loadEventsFromEVEFile(path string) ([]shared.SuricataEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	reader := bufio.NewScanner(file)
	reader.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	events := make([]shared.SuricataEvent, 0)
	for reader.Scan() {
		line := reader.Bytes()
		event, ok := decodeSuricataEVE(line)
		if !ok {
			continue
		}
		events = append(events, event)
	}
	if err := reader.Err(); err != nil {
		return nil, err
	}
	_ = info
	return events, nil
}

func initEVETracker(path, stateFile string) {
	tracker := &eveTracker{
		path:      path,
		stateFile: stateFile,
		state: eveOffsetState{
			Path: path,
		},
	}
	if err := tracker.loadState(); err != nil {
		log.Printf("load eve state failed: file=%s err=%v", stateFile, err)
	}
	eveStateTracker = tracker
}

func initHTTPDataTracker(path, stateFile string) {
	tracker := &httpDataTracker{
		path:      path,
		stateFile: stateFile,
		state: httpDataOffsetState{
			Path: path,
		},
		packets: make(map[string]httpPacketPair),
	}
	if err := tracker.loadState(); err != nil {
		log.Printf("load http-data state failed: file=%s err=%v", stateFile, err)
	}
	httpDataStateTracker = tracker
}

func (t *eveTracker) load() ([]shared.SuricataEvent, error) {
	file, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	currentInode := fileInode(info)
	if t.state.Path != t.path || currentInode != 0 && t.state.Inode != 0 && currentInode != t.state.Inode {
		t.state.Offset = 0
	}
	if info.Size() < t.state.Offset || info.Size() < t.state.Size {
		t.state.Offset = 0
	}
	if _, err := file.Seek(t.state.Offset, io.SeekStart); err != nil {
		return nil, err
	}
	reader := bufio.NewScanner(file)
	reader.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	events := make([]shared.SuricataEvent, 0)
	for reader.Scan() {
		line := reader.Bytes()
		event, ok := decodeSuricataEVE(line)
		if !ok {
			continue
		}
		events = append(events, event)
	}
	if err := reader.Err(); err != nil {
		return nil, err
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err == nil {
		t.state.Offset = offset
	}
	t.state.Path = t.path
	t.state.Size = info.Size()
	t.state.ModTime = info.ModTime().UTC()
	t.state.Inode = currentInode
	if err := t.saveState(); err != nil {
		log.Printf("save eve state failed: file=%s err=%v", t.stateFile, err)
	}
	return events, nil
}

func (t *eveTracker) loadState() error {
	data, err := os.ReadFile(t.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var state eveOffsetState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	t.state = state
	return nil
}

func (t *eveTracker) saveState() error {
	if err := os.MkdirAll(filepath.Dir(t.stateFile), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(t.stateFile, data, 0o644)
}

func (t *httpDataTracker) load() error {
	file, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	currentInode := fileInode(info)
	if t.state.Path != t.path || currentInode != 0 && t.state.Inode != 0 && currentInode != t.state.Inode {
		t.state.Offset = 0
	}
	if info.Size() < t.state.Offset || info.Size() < t.state.Size {
		t.state.Offset = 0
	}
	if _, err := file.Seek(t.state.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewScanner(file)
	reader.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	currentKey := ""
	currentSide := ""
	var packetBytes bytes.Buffer
	flush := func() {
		if currentKey == "" || currentSide == "" || packetBytes.Len() == 0 {
			packetBytes.Reset()
			return
		}
		existing := t.packets[currentKey]
		existing.BaseKey = currentKey
		existing.UpdatedAt = time.Now().UTC()
		text := strings.TrimSpace(strings.ToValidUTF8(packetBytes.String(), ""))
		if currentSide == "request" {
			existing.RequestPacket = text
		} else {
			existing.ResponsePacket = text
		}
		t.packets[currentKey] = existing
		packetBytes.Reset()
	}
	for reader.Scan() {
		line := strings.TrimRight(reader.Text(), "\r")
		if baseKey, side, ok := parseHTTPDataHeader(line); ok {
			flush()
			currentKey = baseKey
			currentSide = side
			continue
		}
		packetBytes.Write(decodeHTTPDataHexLine(line))
	}
	if err := reader.Err(); err != nil {
		return err
	}
	flush()
	offset, err := file.Seek(0, io.SeekCurrent)
	if err == nil {
		t.state.Offset = offset
	}
	t.state.Path = t.path
	t.state.Size = info.Size()
	t.state.ModTime = info.ModTime().UTC()
	t.state.Inode = currentInode
	t.prunePackets()
	return t.saveState()
}

func (t *httpDataTracker) loadState() error {
	data, err := os.ReadFile(t.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var state httpDataOffsetState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	t.state = state
	return nil
}

func (t *httpDataTracker) saveState() error {
	if err := os.MkdirAll(filepath.Dir(t.stateFile), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(t.stateFile, data, 0o644)
}

func (t *httpDataTracker) prunePackets() {
	if len(t.packets) == 0 {
		return
	}
	cutoff := time.Now().UTC().Add(-15 * time.Minute)
	for key, pair := range t.packets {
		if pair.UpdatedAt.Before(cutoff) {
			delete(t.packets, key)
		}
	}
	if len(t.packets) <= 2048 {
		return
	}
	type packetRef struct {
		Key       string
		UpdatedAt time.Time
	}
	items := make([]packetRef, 0, len(t.packets))
	for key, pair := range t.packets {
		items = append(items, packetRef{Key: key, UpdatedAt: pair.UpdatedAt})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].UpdatedAt.Before(items[j].UpdatedAt)
	})
	for len(items) > 2048 {
		delete(t.packets, items[0].Key)
		items = items[1:]
	}
}

func fileInode(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0
	}
	return stat.Ino
}

type suricataEVEAlias struct {
	Timestamp string                `json:"timestamp"`
	EventType string                `json:"event_type"`
	SrcIP     string                `json:"src_ip"`
	SrcPort   int                   `json:"src_port"`
	DstIP     string                `json:"dst_ip"`
	DstPort   int                   `json:"dst_port"`
	DestIP    string                `json:"dest_ip"`
	DestPort  int                   `json:"dest_port"`
	Proto     string                `json:"proto"`
	AppProto  string                `json:"app_proto"`
	Alert     *shared.SuricataAlert `json:"alert,omitempty"`
	FlowID    any                   `json:"flow_id,omitempty"`
	Payload   any                   `json:"payload,omitempty"`
}

func decodeSuricataEVE(line []byte) (shared.SuricataEvent, bool) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return shared.SuricataEvent{}, false
	}
	var alias suricataEVEAlias
	if err := json.Unmarshal(line, &alias); err != nil {
		return shared.SuricataEvent{}, false
	}
	dstIP := strings.TrimSpace(alias.DstIP)
	if dstIP == "" {
		dstIP = strings.TrimSpace(alias.DestIP)
	}
	dstPort := alias.DstPort
	if dstPort == 0 {
		dstPort = alias.DestPort
	}
	return shared.SuricataEvent{
		Timestamp: alias.Timestamp,
		EventType: alias.EventType,
		SrcIP:     alias.SrcIP,
		SrcPort:   alias.SrcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Proto:     alias.Proto,
		AppProto:  alias.AppProto,
		Alert:     alias.Alert,
		FlowID:    normalizeFlowID(alias.FlowID),
		Payload:   raw,
	}, true
}

func enrichEventsWithHTTPPackets(events []shared.SuricataEvent, packets map[string]httpPacketPair) {
	if len(events) == 0 || len(packets) == 0 {
		return
	}
	for index := range events {
		if !isHTTPRelevantEvent(events[index]) {
			continue
		}
		pair, ok := lookupHTTPPacketPair(events[index], packets)
		if !ok {
			continue
		}
		if events[index].Payload == nil {
			events[index].Payload = make(map[string]any)
		}
		events[index].Payload["_ndr_http_packets"] = map[string]any{
			"source":          "http-data.log",
			"request_packet":  pair.RequestPacket,
			"response_packet": pair.ResponsePacket,
		}
	}
}

func isHTTPRelevantEvent(event shared.SuricataEvent) bool {
	if strings.EqualFold(event.AppProto, "http") {
		return true
	}
	if event.Payload == nil {
		return false
	}
	if _, ok := event.Payload["http"].(map[string]any); ok {
		return true
	}
	if _, ok := event.Payload["http"].(map[string]string); ok {
		return true
	}
	return strings.EqualFold(event.EventType, "http") || strings.EqualFold(event.EventType, "fileinfo") || strings.EqualFold(event.EventType, "alert")
}

func lookupHTTPPacketPair(event shared.SuricataEvent, packets map[string]httpPacketPair) (httpPacketPair, bool) {
	candidates := []string{
		httpTupleKey(event.SrcIP, event.SrcPort, event.DstIP, event.DstPort),
		httpTupleKey(event.DstIP, event.DstPort, event.SrcIP, event.SrcPort),
	}
	best := httpPacketPair{}
	bestScore := -1
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		pair, ok := packets[candidate]
		if !ok {
			continue
		}
		score := len(strings.TrimSpace(pair.RequestPacket)) + len(strings.TrimSpace(pair.ResponsePacket))
		if strings.TrimSpace(pair.RequestPacket) != "" {
			score += 1000
		}
		if strings.TrimSpace(pair.ResponsePacket) != "" {
			score += 1000
		}
		if score > bestScore {
			best = pair
			bestScore = score
		}
	}
	return best, bestScore >= 0
}

func httpTupleKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	if strings.TrimSpace(srcIP) == "" || strings.TrimSpace(dstIP) == "" || srcPort <= 0 || dstPort <= 0 {
		return ""
	}
	return fmt.Sprintf("%s_%d-%s_%d", srcIP, srcPort, dstIP, dstPort)
}

func parseHTTPDataHeader(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasSuffix(trimmed, ":") {
		return "", "", false
	}
	trimmed = strings.TrimSuffix(trimmed, ":")
	switch {
	case strings.HasSuffix(trimmed, "-ts"):
		return strings.TrimSuffix(trimmed, "-ts"), "request", true
	case strings.HasSuffix(trimmed, "-tc"):
		return strings.TrimSuffix(trimmed, "-tc"), "response", true
	default:
		return "", "", false
	}
}

func decodeHTTPDataHexLine(line string) []byte {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return nil
	}
	out := make([]byte, 0, 64)
	for _, field := range fields[1:] {
		if len(field) != 2 {
			break
		}
		value, err := strconv.ParseUint(field, 16, 8)
		if err != nil {
			break
		}
		out = append(out, byte(value))
	}
	return out
}

func normalizeFlowID(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func loadDemoEvents() []shared.SuricataEvent {
	if path := os.Getenv("NDR_EVENTS_FILE"); path != "" {
		content, err := os.ReadFile(path)
		if err == nil {
			var events []shared.SuricataEvent
			if err := json.Unmarshal(content, &events); err == nil {
				return events
			}
		}
	}

	now := time.Now().UTC()
	return []shared.SuricataEvent{
		{
			Timestamp: now.Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.0.0.15",
			SrcPort:   52314,
			DstIP:     "192.168.10.8",
			DstPort:   445,
			Proto:     "TCP",
			AppProto:  "smb",
			FlowID:    "flow-demo-01",
			Alert: &shared.SuricataAlert{
				SignatureID: 2026001,
				Signature:   "Potential lateral movement over SMB",
				Category:    "Attempted Admin",
				Severity:    1,
			},
		},
		{
			Timestamp: now.Add(2 * time.Second).Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.0.0.15",
			SrcPort:   52315,
			DstIP:     "192.168.10.8",
			DstPort:   445,
			Proto:     "TCP",
			AppProto:  "smb",
			FlowID:    "flow-demo-02",
			Alert: &shared.SuricataAlert{
				SignatureID: 2026001,
				Signature:   "Potential lateral movement over SMB",
				Category:    "Attempted Admin",
				Severity:    1,
			},
		},
	}
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func countAlertEvents(events []shared.SuricataEvent) int {
	total := 0
	for _, event := range events {
		if event.EventType == "alert" && event.Alert != nil {
			total++
		}
	}
	return total
}

func positiveDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func flushQueuedEvents(serverURL, queueDir string) error {
	batches, err := listQueuedBatches(queueDir)
	if err != nil {
		return err
	}
	for _, item := range batches {
		if err := ingest(serverURL, item.Batch); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(queueDir, item.FileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		log.Printf("queued batch delivered: probe_id=%s file=%s events=%d", item.Batch.ProbeID, item.FileName, len(item.Batch.Events))
	}
	return nil
}

func enqueueBatch(queueDir string, batch shared.EventBatch, maxFiles int, maxBytes int64) error {
	name := fmt.Sprintf("%d-%s.json", time.Now().UTC().UnixNano(), batch.ProbeID)
	path := filepath.Join(queueDir, name)
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return err
	}
	return pruneQueueDir(queueDir, maxFiles, maxBytes)
}

func listQueuedBatches(queueDir string) ([]persistedBatch, error) {
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		return nil, err
	}
	out := make([]persistedBatch, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(queueDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var batch shared.EventBatch
		if err := json.Unmarshal(content, &batch); err != nil {
			continue
		}
		if strings.TrimSpace(batch.TenantID) == "" || strings.TrimSpace(batch.ProbeID) == "" || len(batch.Events) == 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		out = append(out, persistedBatch{FileName: entry.Name(), Size: info.Size(), Batch: batch})
	}
	sort.Slice(out, func(i, j int) bool {
		return queueOrder(out[i].FileName) < queueOrder(out[j].FileName)
	})
	return out, nil
}

func pruneQueueDir(queueDir string, maxFiles int, maxBytes int64) error {
	batches, err := listQueuedBatches(queueDir)
	if err != nil {
		return err
	}
	totalBytes := int64(0)
	for _, batch := range batches {
		totalBytes += batch.Size
	}
	for len(batches) > max(1, maxFiles) || totalBytes > maxBytes {
		if len(batches) == 0 {
			return nil
		}
		oldest := batches[0]
		if err := os.Remove(filepath.Join(queueDir, oldest.FileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		totalBytes -= oldest.Size
		batches = batches[1:]
		log.Printf("buffer pruned: file=%s remaining_files=%d remaining_bytes=%d", oldest.FileName, len(batches), totalBytes)
	}
	return nil
}

func queueOrder(name string) int64 {
	prefix := strings.TrimSuffix(name, filepath.Ext(name))
	prefix = strings.SplitN(prefix, "-", 2)[0]
	value, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func intEnv(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func int64Env(key string, fallback int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
