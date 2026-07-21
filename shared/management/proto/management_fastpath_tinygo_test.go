//go:build tinygo

package proto

import (
	"testing"

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
