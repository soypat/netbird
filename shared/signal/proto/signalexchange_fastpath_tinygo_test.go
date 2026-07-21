//go:build tinygo

package proto

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	goproto "google.golang.org/protobuf/proto"
)

func TestSignalExchangeFastPathRoundTrip(t *testing.T) {
	direct := false
	relayAddr := "relay.example.com:443"

	msg := &Message{
		Key:       "local",
		RemoteKey: "remote",
		Body: &Body{
			Type:              Body_ANSWER,
			Payload:           "payload",
			WgListenPort:      51820,
			NetBirdVersion:    "test",
			Mode:              &Mode{Direct: &direct},
			FeaturesSupported: []uint32{1, 2, 300},
			RosenpassConfig: &RosenpassConfig{
				RosenpassPubKey:     []byte{1, 2, 3},
				RosenpassServerAddr: "127.0.0.1:1234",
			},
			RelayServerAddress: &relayAddr,
			SessionId:          []byte{4, 5, 6},
			RelayServerIP:      []byte{127, 0, 0, 1},
		},
	}

	wire, err := goproto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	if got, want := len(wire), goproto.Size(msg); got != want {
		t.Fatalf("size mismatch: got %d want %d", got, want)
	}

	var out Message
	if err := goproto.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal message: %v", err)
	}
	if !goproto.Equal(msg, &out) {
		t.Fatalf("roundtrip mismatch: %#v != %#v", msg, &out)
	}

	clone, ok := goproto.Clone(msg).(*Message)
	if !ok {
		t.Fatalf("clone type %T", clone)
	}
	if !goproto.Equal(msg, clone) {
		t.Fatalf("clone mismatch: %#v != %#v", msg, clone)
	}
}

func TestEncryptedMessageFastPathRoundTrip(t *testing.T) {
	msg := &EncryptedMessage{
		Key:       "local",
		RemoteKey: "remote",
		Body:      []byte{1, 2, 3, 4},
	}

	wire, err := goproto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal encrypted message: %v", err)
	}

	var out EncryptedMessage
	if err := goproto.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal encrypted message: %v", err)
	}
	if !goproto.Equal(msg, &out) {
		t.Fatalf("roundtrip mismatch: %#v != %#v", msg, &out)
	}
}

func TestSignalFastPathPreservesUnknownFields(t *testing.T) {
	msg := &EncryptedMessage{
		Key:       "local",
		RemoteKey: "remote",
		Body:      []byte{1, 2, 3, 4},
	}

	wire, err := goproto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal encrypted message: %v", err)
	}
	unknown := protowire.AppendTag(nil, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 12345)
	wire = append(wire, unknown...)

	var out EncryptedMessage
	if err := goproto.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal encrypted message with unknown field: %v", err)
	}
	if got := out.ProtoReflect().GetUnknown(); !bytes.Equal(got, unknown) {
		t.Fatalf("unknown fields mismatch: got %x want %x", got, unknown)
	}

	roundtrip, err := goproto.Marshal(&out)
	if err != nil {
		t.Fatalf("marshal encrypted message after unknown field: %v", err)
	}
	if !bytes.Equal(roundtrip, wire) {
		t.Fatalf("wire mismatch after unknown field roundtrip: got %x want %x", roundtrip, wire)
	}
}
