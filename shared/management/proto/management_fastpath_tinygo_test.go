//go:build tinygo

package proto

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	goproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func TestManagementLoginFastPathRoundTrip(t *testing.T) {
	req := &LoginRequest{
		SetupKey: "setup",
		Meta: &PeerSystemMeta{
			Hostname:       "host",
			GoOS:           "js",
			NetbirdVersion: "test",
			Environment:    &Environment{Cloud: "local", Platform: "wasm"},
			Files:          []*File{{Path: "/tmp/a", Exist: true}},
			Flags:          &Flags{DisableIPv6: true, ServerSSHAllowed: true},
			Capabilities:   []PeerCapability{PeerCapability_PeerCapabilitySourcePrefixes, PeerCapability_PeerCapabilityIPv6Overlay},
		},
		JwtToken:  "jwt",
		PeerKeys:  &PeerKeys{SshPubKey: []byte("ssh"), WgPubKey: []byte("wg")},
		DnsLabels: []string{"a.example", "b.example"},
	}
	assertProtoRoundTrip(t, req, &LoginRequest{})

	resp := &LoginResponse{
		NetbirdConfig: &NetbirdConfig{
			Stuns: []*HostConfig{{Uri: "stun:example", Protocol: HostConfig_UDP}},
			Turns: []*ProtectedHostConfig{{
				HostConfig: &HostConfig{Uri: "turn:example", Protocol: HostConfig_TCP},
				User:       "user",
				Password:   "pass",
			}},
			Signal: &HostConfig{Uri: "signal:example", Protocol: HostConfig_HTTPS},
			Relay:  &RelayConfig{Urls: []string{"relay.example"}, TokenPayload: "payload", TokenSignature: "sig"},
			Flow: &FlowConfig{
				Url:                "flow.example",
				Interval:           durationpb.New(5 * time.Second),
				Enabled:            true,
				Counters:           true,
				ExitNodeCollection: true,
				DnsCollection:      true,
			},
		},
		PeerConfig: &PeerConfig{
			Address:                         "100.64.0.1/32",
			Dns:                             "100.64.0.2",
			SshConfig:                       &SSHConfig{SshEnabled: true, SshPubKey: []byte("ssh"), JwtConfig: &JWTConfig{Issuer: "issuer", Audiences: []string{"aud"}}},
			Fqdn:                            "peer.netbird.cloud",
			RoutingPeerDnsResolutionEnabled: true,
			LazyConnectionEnabled:           true,
			Mtu:                             1280,
			AutoUpdate:                      &AutoUpdateSettings{Version: "v1", AlwaysUpdate: true},
			AddressV6:                       []byte{1, 2, 3},
		},
		Checks:           []*Checks{{Files: []string{"/a", "/b"}}},
		SessionExpiresAt: timestamppb.New(time.Unix(100, 20)),
	}
	assertProtoRoundTrip(t, resp, &LoginResponse{})
}

func TestManagementAuthFlowFastPathRoundTrip(t *testing.T) {
	assertProtoRoundTrip(t, &Empty{}, &Empty{})
	assertProtoRoundTrip(t, &SyncRequest{Meta: &PeerSystemMeta{Hostname: "host"}}, &SyncRequest{})
	assertProtoRoundTrip(t, &SyncMetaRequest{Meta: &PeerSystemMeta{Hostname: "host"}}, &SyncMetaRequest{})
	assertProtoRoundTrip(t, &ServerKeyResponse{Key: "server", ExpiresAt: timestamppb.New(time.Unix(200, 0)), Version: 3}, &ServerKeyResponse{})
	assertProtoRoundTrip(t, &ExtendAuthSessionRequest{JwtToken: "jwt", Meta: &PeerSystemMeta{Hostname: "host"}}, &ExtendAuthSessionRequest{})
	assertProtoRoundTrip(t, &ExtendAuthSessionResponse{SessionExpiresAt: timestamppb.New(time.Unix(300, 0))}, &ExtendAuthSessionResponse{})
	assertProtoRoundTrip(t, &DeviceAuthorizationFlowRequest{}, &DeviceAuthorizationFlowRequest{})
	assertProtoRoundTrip(t, &DeviceAuthorizationFlow{
		Provider: DeviceAuthorizationFlow_HOSTED,
		ProviderConfig: &ProviderConfig{
			ClientID:           "client",
			DeviceAuthEndpoint: "device",
			TokenEndpoint:      "token",
			Scope:              "openid",
			UseIDToken:         true,
		},
	}, &DeviceAuthorizationFlow{})
	assertProtoRoundTrip(t, &PKCEAuthorizationFlowRequest{}, &PKCEAuthorizationFlowRequest{})
	assertProtoRoundTrip(t, &PKCEAuthorizationFlow{ProviderConfig: &ProviderConfig{
		ClientID:              "client",
		AuthorizationEndpoint: "auth",
		RedirectURLs:          []string{"http://127.0.0.1/callback"},
		DisablePromptLogin:    true,
		LoginFlag:             1,
	}}, &PKCEAuthorizationFlow{})
}

func assertProtoRoundTrip(t *testing.T, in goproto.Message, out goproto.Message) {
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
