//go:build tinygo

package proto

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	goproto "google.golang.org/protobuf/proto"
)

func TestManagementEncryptedMessageFastPathRoundTrip(t *testing.T) {
	msg := &EncryptedMessage{
		WgPubKey: "peer",
		Body:     []byte{1, 2, 3},
		Version:  2,
	}

	wire, err := goproto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := len(wire), goproto.Size(msg); got != want {
		t.Fatalf("size mismatch: got %d want %d", got, want)
	}

	var out EncryptedMessage
	if err := goproto.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !goproto.Equal(msg, &out) {
		t.Fatalf("roundtrip mismatch: %#v != %#v", msg, &out)
	}
}

func TestManagementFastPathPreservesUnknownFields(t *testing.T) {
	msg := &EncryptedMessage{
		WgPubKey: "peer",
		Body:     []byte{1, 2, 3},
		Version:  2,
	}

	wire, err := goproto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	unknown := protowire.AppendTag(nil, 99, protowire.BytesType)
	unknown = protowire.AppendString(unknown, "future")
	wire = append(wire, unknown...)

	var out EncryptedMessage
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
