package main

import "testing"

func TestDecodeSuricataEVEWithStringPayload(t *testing.T) {
	line := []byte(`{"timestamp":"2026-03-11T08:40:05.619508+0000","flow_id":1478515316003721,"event_type":"alert","src_ip":"192.168.2.186","src_port":56077,"dest_ip":"192.168.2.88","dest_port":80,"proto":"TCP","app_proto":"http","alert":{"signature_id":2063343,"signature":"ET EXPLOIT Apache CouchDB 1.7.0 / 2.x < 2.1.1 - Remote Privilege Escalation (CVE-2017-12635)","category":"Attempted Administrator Privilege Gain","severity":1},"payload":"UFVUIC8=","payload_printable":"PUT /","http":{"http_method":"PUT"}}`)

	event, ok := decodeSuricataEVE(line)
	if !ok {
		t.Fatal("expected decodeSuricataEVE to parse event with string payload")
	}
	if event.EventType != "alert" {
		t.Fatalf("unexpected event type: %s", event.EventType)
	}
	if event.Alert == nil {
		t.Fatal("expected alert to be present")
	}
	if event.FlowID != "1478515316003721" {
		t.Fatalf("unexpected flow_id: %s", event.FlowID)
	}
	if payload, ok := event.Payload["payload"].(string); !ok || payload == "" {
		t.Fatalf("expected raw payload string to be preserved, got %#v", event.Payload["payload"])
	}
}
