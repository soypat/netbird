//go:build tinygo

package proto

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	goproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFlowEventFastPathRoundTripWithPorts(t *testing.T) {
	msg := &FlowEvent{
		EventId:   []byte("event-port"),
		Timestamp: timestamppb.New(time.Unix(100, 20)),
		PublicKey: []byte("peer-key"),
		FlowFields: &FlowFields{
			FlowId:           []byte("flow-id"),
			Type:             Type_TYPE_START,
			RuleId:           []byte("rule-id"),
			Direction:        Direction_EGRESS,
			Protocol:         6,
			SourceIp:         []byte{100, 64, 0, 1},
			DestIp:           []byte{100, 64, 0, 2},
			ConnectionInfo:   &FlowFields_PortInfo{PortInfo: &PortInfo{SourcePort: 12345, DestPort: 443}},
			RxPackets:        1,
			TxPackets:        2,
			RxBytes:          100,
			TxBytes:          200,
			SourceResourceId: []byte("source-resource"),
			DestResourceId:   []byte("dest-resource"),
		},
		IsInitiator: true,
	}

	assertFlowProtoRoundTrip(t, msg, &FlowEvent{})
}

func TestFlowEventFastPathRoundTripWithICMP(t *testing.T) {
	msg := &FlowEvent{
		EventId:   []byte("event-icmp"),
		Timestamp: timestamppb.New(time.Unix(200, 30)),
		PublicKey: []byte("peer-key"),
		FlowFields: &FlowFields{
			FlowId:         []byte("flow-id"),
			Type:           Type_TYPE_DROP,
			Direction:      Direction_INGRESS,
			Protocol:       1,
			SourceIp:       []byte{10, 0, 0, 1},
			DestIp:         []byte{10, 0, 0, 2},
			ConnectionInfo: &FlowFields_IcmpInfo{IcmpInfo: &ICMPInfo{IcmpType: 8, IcmpCode: 0}},
			RxPackets:      3,
			TxPackets:      4,
			RxBytes:        300,
			TxBytes:        400,
		},
	}

	assertFlowProtoRoundTrip(t, msg, &FlowEvent{})
}

func TestFlowEventAckFastPathRoundTrip(t *testing.T) {
	assertFlowProtoRoundTrip(t, &FlowEventAck{
		EventId:     []byte("event-id"),
		IsInitiator: true,
	}, &FlowEventAck{})
}

func TestFlowFastPathPreservesUnknownFields(t *testing.T) {
	msg := &FlowEventAck{
		EventId:     []byte("event-id"),
		IsInitiator: true,
	}

	wire, err := goproto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	unknown := protowire.AppendTag(nil, 99, protowire.BytesType)
	unknown = protowire.AppendString(unknown, "future")
	wire = append(wire, unknown...)

	var out FlowEventAck
	if err := goproto.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal with unknown field: %v", err)
	}
	if got := out.ProtoReflect().GetUnknown(); !bytes.Equal(got, unknown) {
		t.Fatalf("unknown fields mismatch: got %x want %x", got, unknown)
	}

	roundtrip, err := goproto.Marshal(&out)
	if err != nil {
		t.Fatalf("marshal after unknown field: %v", err)
	}
	if !bytes.Equal(roundtrip, wire) {
		t.Fatalf("wire mismatch after unknown field roundtrip: got %x want %x", roundtrip, wire)
	}
}

func assertFlowProtoRoundTrip(t *testing.T, in goproto.Message, out goproto.Message) {
	t.Helper()

	wire, err := goproto.Marshal(in)
	if err != nil {
		t.Fatalf("marshal %T: %v", in, err)
	}
	if got, want := len(wire), goproto.Size(in); got != want {
		t.Fatalf("size mismatch for %T: got %d want %d", in, got, want)
	}
	if err := goproto.Unmarshal(wire, out); err != nil {
		t.Fatalf("unmarshal %T: %v", in, err)
	}
	if !goproto.Equal(in, out) {
		t.Fatalf("roundtrip mismatch for %T: %#v != %#v", in, in, out)
	}
}
