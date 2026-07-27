package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
)

type scalarKind string

const (
	kindString          scalarKind = "string"
	kindBytes           scalarKind = "bytes"
	kindBool            scalarKind = "bool"
	kindInt32           scalarKind = "int32"
	kindInt64           scalarKind = "int64"
	kindUint32          scalarKind = "uint32"
	kindUint64          scalarKind = "uint64"
	kindEnum            scalarKind = "enum"
	kindMessage         scalarKind = "message"
	kindRepeatedUint32  scalarKind = "repeated_uint32"
	kindRepeatedEnum    scalarKind = "repeated_enum"
	kindRepeatedString  scalarKind = "repeated_string"
	kindRepeatedBytes   scalarKind = "repeated_bytes"
	kindRepeatedMsg     scalarKind = "repeated_message"
	kindMapStringMsg    scalarKind = "map_string_message"
	kindMapStringString scalarKind = "map_string_string"
	kindPortInfoOneof   scalarKind = "port_info_oneof"
	kindJobReqOneof     scalarKind = "job_request_oneof"
	kindJobRespOneof    scalarKind = "job_response_oneof"
	kindFlowFieldsOneof scalarKind = "flow_fields_oneof"
	kindAuthReqOneof    scalarKind = "authenticate_request_oneof"
	kindSyncMapReqOneof scalarKind = "sync_mappings_request_oneof"
	kindOptionalString  scalarKind = "optional_string"
	kindOptionalBytes   scalarKind = "optional_bytes"
	kindOptionalBool    scalarKind = "optional_bool"
	kindTimestamp       scalarKind = "timestamp"
	kindDuration        scalarKind = "duration"
)

type field struct {
	Number      int
	Name        string
	Kind        scalarKind
	MessageType string
	EnumType    string
}

type message struct {
	Name   string
	Fields []field
}

type target struct {
	Name                string
	Package             string
	Canary              string
	Prefix              string
	OutputDir           string
	PBFile              string
	Messages            []message
	TestSource          string
	ReusePackageHelpers bool
}

var targets = map[string]target{
	"signal": {
		Name:      "signal",
		Package:   "proto",
		Canary:    "signal proto fast-path",
		Prefix:    "signalexchange",
		OutputDir: "shared/signal/proto",
		PBFile:    "signalexchange.pb.go",
		Messages: []message{
			{Name: "EncryptedMessage", Fields: []field{
				{Number: 2, Name: "Key", Kind: kindString},
				{Number: 3, Name: "RemoteKey", Kind: kindString},
				{Number: 4, Name: "Body", Kind: kindBytes},
			}},
			{Name: "Message", Fields: []field{
				{Number: 2, Name: "Key", Kind: kindString},
				{Number: 3, Name: "RemoteKey", Kind: kindString},
				{Number: 4, Name: "Body", Kind: kindMessage, MessageType: "Body"},
			}},
			{Name: "Body", Fields: []field{
				{Number: 1, Name: "Type", Kind: kindEnum, EnumType: "Body_Type"},
				{Number: 2, Name: "Payload", Kind: kindString},
				{Number: 3, Name: "WgListenPort", Kind: kindUint32},
				{Number: 4, Name: "NetBirdVersion", Kind: kindString},
				{Number: 5, Name: "Mode", Kind: kindMessage, MessageType: "Mode"},
				{Number: 6, Name: "FeaturesSupported", Kind: kindRepeatedUint32},
				{Number: 7, Name: "RosenpassConfig", Kind: kindMessage, MessageType: "RosenpassConfig"},
				{Number: 8, Name: "RelayServerAddress", Kind: kindOptionalString},
				{Number: 10, Name: "SessionId", Kind: kindOptionalBytes},
				{Number: 11, Name: "RelayServerIP", Kind: kindOptionalBytes},
			}},
			{Name: "Mode", Fields: []field{
				{Number: 1, Name: "Direct", Kind: kindOptionalBool},
			}},
			{Name: "RosenpassConfig", Fields: []field{
				{Number: 1, Name: "RosenpassPubKey", Kind: kindBytes},
				{Number: 2, Name: "RosenpassServerAddr", Kind: kindString},
			}},
		},
	},
	"management": {
		Name:      "management",
		Package:   "proto",
		Canary:    "management proto fast-path",
		Prefix:    "management",
		OutputDir: "shared/management/proto",
		PBFile:    "management.pb.go",
		Messages: []message{
			{Name: "EncryptedMessage", Fields: []field{
				{Number: 1, Name: "WgPubKey", Kind: kindString},
				{Number: 2, Name: "Body", Kind: kindBytes},
				{Number: 3, Name: "Version", Kind: kindInt32},
			}},
			{Name: "JobRequest", Fields: []field{
				{Number: 1, Name: "ID", Kind: kindBytes},
				{Number: 0, Name: "WorkloadParameters", Kind: kindJobReqOneof},
			}},
			{Name: "JobResponse", Fields: []field{
				{Number: 1, Name: "ID", Kind: kindBytes},
				{Number: 2, Name: "Status", Kind: kindEnum, EnumType: "JobStatus"},
				{Number: 3, Name: "Reason", Kind: kindBytes},
				{Number: 0, Name: "WorkloadResults", Kind: kindJobRespOneof},
			}},
			{Name: "BundleParameters", Fields: []field{
				{Number: 1, Name: "BundleFor", Kind: kindBool},
				{Number: 2, Name: "BundleForTime", Kind: kindInt64},
				{Number: 3, Name: "LogFileCount", Kind: kindInt32},
				{Number: 4, Name: "Anonymize", Kind: kindBool},
			}},
			{Name: "BundleResult", Fields: []field{
				{Number: 1, Name: "UploadKey", Kind: kindString},
			}},
			{Name: "SyncRequest", Fields: []field{
				{Number: 1, Name: "Meta", Kind: kindMessage, MessageType: "PeerSystemMeta"},
			}},
			{Name: "SyncMetaRequest", Fields: []field{
				{Number: 1, Name: "Meta", Kind: kindMessage, MessageType: "PeerSystemMeta"},
			}},
			{Name: "LoginRequest", Fields: []field{
				{Number: 1, Name: "SetupKey", Kind: kindString},
				{Number: 2, Name: "Meta", Kind: kindMessage, MessageType: "PeerSystemMeta"},
				{Number: 3, Name: "JwtToken", Kind: kindString},
				{Number: 4, Name: "PeerKeys", Kind: kindMessage, MessageType: "PeerKeys"},
				{Number: 5, Name: "DnsLabels", Kind: kindRepeatedString},
			}},
			{Name: "PeerKeys", Fields: []field{
				{Number: 1, Name: "SshPubKey", Kind: kindBytes},
				{Number: 2, Name: "WgPubKey", Kind: kindBytes},
			}},
			{Name: "Environment", Fields: []field{
				{Number: 1, Name: "Cloud", Kind: kindString},
				{Number: 2, Name: "Platform", Kind: kindString},
			}},
			{Name: "File", Fields: []field{
				{Number: 1, Name: "Path", Kind: kindString},
				{Number: 2, Name: "Exist", Kind: kindBool},
				{Number: 3, Name: "ProcessIsRunning", Kind: kindBool},
			}},
			{Name: "Flags", Fields: []field{
				{Number: 1, Name: "RosenpassEnabled", Kind: kindBool},
				{Number: 2, Name: "RosenpassPermissive", Kind: kindBool},
				{Number: 3, Name: "ServerSSHAllowed", Kind: kindBool},
				{Number: 4, Name: "DisableClientRoutes", Kind: kindBool},
				{Number: 5, Name: "DisableServerRoutes", Kind: kindBool},
				{Number: 6, Name: "DisableDNS", Kind: kindBool},
				{Number: 7, Name: "DisableFirewall", Kind: kindBool},
				{Number: 8, Name: "BlockLANAccess", Kind: kindBool},
				{Number: 9, Name: "BlockInbound", Kind: kindBool},
				{Number: 10, Name: "LazyConnectionEnabled", Kind: kindBool},
				{Number: 11, Name: "EnableSSHRoot", Kind: kindBool},
				{Number: 12, Name: "EnableSSHSFTP", Kind: kindBool},
				{Number: 13, Name: "EnableSSHLocalPortForwarding", Kind: kindBool},
				{Number: 14, Name: "EnableSSHRemotePortForwarding", Kind: kindBool},
				{Number: 15, Name: "DisableSSHAuth", Kind: kindBool},
				{Number: 16, Name: "DisableIPv6", Kind: kindBool},
			}},
			{Name: "PeerSystemMeta", Fields: []field{
				{Number: 1, Name: "Hostname", Kind: kindString},
				{Number: 2, Name: "GoOS", Kind: kindString},
				{Number: 3, Name: "Kernel", Kind: kindString},
				{Number: 4, Name: "Core", Kind: kindString},
				{Number: 5, Name: "Platform", Kind: kindString},
				{Number: 6, Name: "OS", Kind: kindString},
				{Number: 7, Name: "NetbirdVersion", Kind: kindString},
				{Number: 8, Name: "UiVersion", Kind: kindString},
				{Number: 9, Name: "KernelVersion", Kind: kindString},
				{Number: 10, Name: "OSVersion", Kind: kindString},
				{Number: 11, Name: "NetworkAddresses", Kind: kindRepeatedMsg, MessageType: "NetworkAddress"},
				{Number: 12, Name: "SysSerialNumber", Kind: kindString},
				{Number: 13, Name: "SysProductName", Kind: kindString},
				{Number: 14, Name: "SysManufacturer", Kind: kindString},
				{Number: 15, Name: "Environment", Kind: kindMessage, MessageType: "Environment"},
				{Number: 16, Name: "Files", Kind: kindRepeatedMsg, MessageType: "File"},
				{Number: 17, Name: "Flags", Kind: kindMessage, MessageType: "Flags"},
				{Number: 18, Name: "Capabilities", Kind: kindRepeatedEnum, EnumType: "PeerCapability"},
			}},
			{Name: "LoginResponse", Fields: []field{
				{Number: 1, Name: "NetbirdConfig", Kind: kindMessage, MessageType: "NetbirdConfig"},
				{Number: 2, Name: "PeerConfig", Kind: kindMessage, MessageType: "PeerConfig"},
				{Number: 3, Name: "Checks", Kind: kindRepeatedMsg, MessageType: "Checks"},
				{Number: 4, Name: "SessionExpiresAt", Kind: kindTimestamp},
			}},
			{Name: "SyncResponse", Fields: []field{
				{Number: 1, Name: "NetbirdConfig", Kind: kindMessage, MessageType: "NetbirdConfig"},
				{Number: 2, Name: "PeerConfig", Kind: kindMessage, MessageType: "PeerConfig"},
				{Number: 3, Name: "RemotePeers", Kind: kindRepeatedMsg, MessageType: "RemotePeerConfig"},
				{Number: 4, Name: "RemotePeersIsEmpty", Kind: kindBool},
				{Number: 5, Name: "NetworkMap", Kind: kindMessage, MessageType: "NetworkMap"},
				{Number: 6, Name: "Checks", Kind: kindRepeatedMsg, MessageType: "Checks"},
				{Number: 7, Name: "SessionExpiresAt", Kind: kindTimestamp},
			}},
			{Name: "ExtendAuthSessionRequest", Fields: []field{
				{Number: 1, Name: "JwtToken", Kind: kindString},
				{Number: 2, Name: "Meta", Kind: kindMessage, MessageType: "PeerSystemMeta"},
			}},
			{Name: "ExtendAuthSessionResponse", Fields: []field{
				{Number: 1, Name: "SessionExpiresAt", Kind: kindTimestamp},
			}},
			{Name: "ServerKeyResponse", Fields: []field{
				{Number: 1, Name: "Key", Kind: kindString},
				{Number: 2, Name: "ExpiresAt", Kind: kindTimestamp},
				{Number: 3, Name: "Version", Kind: kindInt32},
			}},
			{Name: "Empty"},
			{Name: "NetbirdConfig", Fields: []field{
				{Number: 1, Name: "Stuns", Kind: kindRepeatedMsg, MessageType: "HostConfig"},
				{Number: 2, Name: "Turns", Kind: kindRepeatedMsg, MessageType: "ProtectedHostConfig"},
				{Number: 3, Name: "Signal", Kind: kindMessage, MessageType: "HostConfig"},
				{Number: 4, Name: "Relay", Kind: kindMessage, MessageType: "RelayConfig"},
				{Number: 5, Name: "Flow", Kind: kindMessage, MessageType: "FlowConfig"},
			}},
			{Name: "HostConfig", Fields: []field{
				{Number: 1, Name: "Uri", Kind: kindString},
				{Number: 2, Name: "Protocol", Kind: kindEnum, EnumType: "HostConfig_Protocol"},
			}},
			{Name: "RelayConfig", Fields: []field{
				{Number: 1, Name: "Urls", Kind: kindRepeatedString},
				{Number: 2, Name: "TokenPayload", Kind: kindString},
				{Number: 3, Name: "TokenSignature", Kind: kindString},
			}},
			{Name: "FlowConfig", Fields: []field{
				{Number: 1, Name: "Url", Kind: kindString},
				{Number: 2, Name: "TokenPayload", Kind: kindString},
				{Number: 3, Name: "TokenSignature", Kind: kindString},
				{Number: 4, Name: "Interval", Kind: kindDuration},
				{Number: 5, Name: "Enabled", Kind: kindBool},
				{Number: 6, Name: "Counters", Kind: kindBool},
				{Number: 7, Name: "ExitNodeCollection", Kind: kindBool},
				{Number: 8, Name: "DnsCollection", Kind: kindBool},
			}},
			{Name: "JWTConfig", Fields: []field{
				{Number: 1, Name: "Issuer", Kind: kindString},
				{Number: 2, Name: "Audience", Kind: kindString},
				{Number: 3, Name: "KeysLocation", Kind: kindString},
				{Number: 4, Name: "MaxTokenAge", Kind: kindInt64},
				{Number: 5, Name: "Audiences", Kind: kindRepeatedString},
			}},
			{Name: "ProtectedHostConfig", Fields: []field{
				{Number: 1, Name: "HostConfig", Kind: kindMessage, MessageType: "HostConfig"},
				{Number: 2, Name: "User", Kind: kindString},
				{Number: 3, Name: "Password", Kind: kindString},
			}},
			{Name: "PeerConfig", Fields: []field{
				{Number: 1, Name: "Address", Kind: kindString},
				{Number: 2, Name: "Dns", Kind: kindString},
				{Number: 3, Name: "SshConfig", Kind: kindMessage, MessageType: "SSHConfig"},
				{Number: 4, Name: "Fqdn", Kind: kindString},
				{Number: 5, Name: "RoutingPeerDnsResolutionEnabled", Kind: kindBool},
				{Number: 6, Name: "LazyConnectionEnabled", Kind: kindBool},
				{Number: 7, Name: "Mtu", Kind: kindInt32},
				{Number: 8, Name: "AutoUpdate", Kind: kindMessage, MessageType: "AutoUpdateSettings"},
				{Number: 9, Name: "AddressV6", Kind: kindBytes},
			}},
			{Name: "AutoUpdateSettings", Fields: []field{
				{Number: 1, Name: "Version", Kind: kindString},
				{Number: 2, Name: "AlwaysUpdate", Kind: kindBool},
			}},
			{Name: "NetworkMap", Fields: []field{
				{Number: 1, Name: "Serial", Kind: kindUint64},
				{Number: 2, Name: "PeerConfig", Kind: kindMessage, MessageType: "PeerConfig"},
				{Number: 3, Name: "RemotePeers", Kind: kindRepeatedMsg, MessageType: "RemotePeerConfig"},
				{Number: 4, Name: "RemotePeersIsEmpty", Kind: kindBool},
				{Number: 5, Name: "Routes", Kind: kindRepeatedMsg, MessageType: "Route"},
				{Number: 6, Name: "DNSConfig", Kind: kindMessage, MessageType: "DNSConfig"},
				{Number: 7, Name: "OfflinePeers", Kind: kindRepeatedMsg, MessageType: "RemotePeerConfig"},
				{Number: 8, Name: "FirewallRules", Kind: kindRepeatedMsg, MessageType: "FirewallRule"},
				{Number: 9, Name: "FirewallRulesIsEmpty", Kind: kindBool},
				{Number: 10, Name: "RoutesFirewallRules", Kind: kindRepeatedMsg, MessageType: "RouteFirewallRule"},
				{Number: 11, Name: "RoutesFirewallRulesIsEmpty", Kind: kindBool},
				{Number: 12, Name: "ForwardingRules", Kind: kindRepeatedMsg, MessageType: "ForwardingRule"},
				{Number: 13, Name: "SshAuth", Kind: kindMessage, MessageType: "SSHAuth"},
			}},
			{Name: "SSHAuth", Fields: []field{
				{Number: 1, Name: "UserIDClaim", Kind: kindString},
				{Number: 2, Name: "AuthorizedUsers", Kind: kindRepeatedBytes},
				{Number: 3, Name: "MachineUsers", Kind: kindMapStringMsg, MessageType: "MachineUserIndexes"},
			}},
			{Name: "MachineUserIndexes", Fields: []field{
				{Number: 1, Name: "Indexes", Kind: kindRepeatedUint32},
			}},
			{Name: "RemotePeerConfig", Fields: []field{
				{Number: 1, Name: "WgPubKey", Kind: kindString},
				{Number: 2, Name: "AllowedIps", Kind: kindRepeatedString},
				{Number: 3, Name: "SshConfig", Kind: kindMessage, MessageType: "SSHConfig"},
				{Number: 4, Name: "Fqdn", Kind: kindString},
				{Number: 5, Name: "AgentVersion", Kind: kindString},
			}},
			{Name: "Route", Fields: []field{
				{Number: 1, Name: "ID", Kind: kindString},
				{Number: 2, Name: "Network", Kind: kindString},
				{Number: 3, Name: "NetworkType", Kind: kindInt64},
				{Number: 4, Name: "Peer", Kind: kindString},
				{Number: 5, Name: "Metric", Kind: kindInt64},
				{Number: 6, Name: "Masquerade", Kind: kindBool},
				{Number: 7, Name: "NetID", Kind: kindString},
				{Number: 8, Name: "Domains", Kind: kindRepeatedString},
				{Number: 9, Name: "KeepRoute", Kind: kindBool},
				{Number: 10, Name: "SkipAutoApply", Kind: kindBool},
			}},
			{Name: "DNSConfig", Fields: []field{
				{Number: 1, Name: "ServiceEnable", Kind: kindBool},
				{Number: 2, Name: "NameServerGroups", Kind: kindRepeatedMsg, MessageType: "NameServerGroup"},
				{Number: 3, Name: "CustomZones", Kind: kindRepeatedMsg, MessageType: "CustomZone"},
				{Number: 4, Name: "ForwarderPort", Kind: kindInt64},
			}},
			{Name: "CustomZone", Fields: []field{
				{Number: 1, Name: "Domain", Kind: kindString},
				{Number: 2, Name: "Records", Kind: kindRepeatedMsg, MessageType: "SimpleRecord"},
				{Number: 3, Name: "SearchDomainDisabled", Kind: kindBool},
				{Number: 4, Name: "NonAuthoritative", Kind: kindBool},
			}},
			{Name: "SimpleRecord", Fields: []field{
				{Number: 1, Name: "Name", Kind: kindString},
				{Number: 2, Name: "Type", Kind: kindInt64},
				{Number: 3, Name: "Class", Kind: kindString},
				{Number: 4, Name: "TTL", Kind: kindInt64},
				{Number: 5, Name: "RData", Kind: kindString},
			}},
			{Name: "NameServerGroup", Fields: []field{
				{Number: 1, Name: "NameServers", Kind: kindRepeatedMsg, MessageType: "NameServer"},
				{Number: 2, Name: "Primary", Kind: kindBool},
				{Number: 3, Name: "Domains", Kind: kindRepeatedString},
				{Number: 4, Name: "SearchDomainsEnabled", Kind: kindBool},
			}},
			{Name: "NameServer", Fields: []field{
				{Number: 1, Name: "IP", Kind: kindString},
				{Number: 2, Name: "NSType", Kind: kindInt64},
				{Number: 3, Name: "Port", Kind: kindInt64},
			}},
			{Name: "FirewallRule", Fields: []field{
				{Number: 1, Name: "PeerIP", Kind: kindString},
				{Number: 2, Name: "Direction", Kind: kindEnum, EnumType: "RuleDirection"},
				{Number: 3, Name: "Action", Kind: kindEnum, EnumType: "RuleAction"},
				{Number: 4, Name: "Protocol", Kind: kindEnum, EnumType: "RuleProtocol"},
				{Number: 5, Name: "Port", Kind: kindString},
				{Number: 6, Name: "PortInfo", Kind: kindMessage, MessageType: "PortInfo"},
				{Number: 7, Name: "PolicyID", Kind: kindBytes},
				{Number: 8, Name: "CustomProtocol", Kind: kindUint32},
				{Number: 9, Name: "SourcePrefixes", Kind: kindRepeatedBytes},
			}},
			{Name: "NetworkAddress", Fields: []field{
				{Number: 1, Name: "NetIP", Kind: kindString},
				{Number: 2, Name: "Mac", Kind: kindString},
			}},
			{Name: "SSHConfig", Fields: []field{
				{Number: 1, Name: "SshEnabled", Kind: kindBool},
				{Number: 2, Name: "SshPubKey", Kind: kindBytes},
				{Number: 3, Name: "JwtConfig", Kind: kindMessage, MessageType: "JWTConfig"},
			}},
			{Name: "Checks", Fields: []field{
				{Number: 1, Name: "Files", Kind: kindRepeatedString},
			}},
			{Name: "PortInfo", Fields: []field{
				{Number: 0, Name: "PortSelection", Kind: kindPortInfoOneof},
			}},
			{Name: "PortInfo_Range", Fields: []field{
				{Number: 1, Name: "Start", Kind: kindUint32},
				{Number: 2, Name: "End", Kind: kindUint32},
			}},
			{Name: "RouteFirewallRule", Fields: []field{
				{Number: 1, Name: "SourceRanges", Kind: kindRepeatedString},
				{Number: 2, Name: "Action", Kind: kindEnum, EnumType: "RuleAction"},
				{Number: 3, Name: "Destination", Kind: kindString},
				{Number: 4, Name: "Protocol", Kind: kindEnum, EnumType: "RuleProtocol"},
				{Number: 5, Name: "PortInfo", Kind: kindMessage, MessageType: "PortInfo"},
				{Number: 6, Name: "IsDynamic", Kind: kindBool},
				{Number: 7, Name: "Domains", Kind: kindRepeatedString},
				{Number: 8, Name: "CustomProtocol", Kind: kindUint32},
				{Number: 9, Name: "PolicyID", Kind: kindBytes},
				{Number: 10, Name: "RouteID", Kind: kindString},
			}},
			{Name: "ForwardingRule", Fields: []field{
				{Number: 1, Name: "Protocol", Kind: kindEnum, EnumType: "RuleProtocol"},
				{Number: 2, Name: "DestinationPort", Kind: kindMessage, MessageType: "PortInfo"},
				{Number: 3, Name: "TranslatedAddress", Kind: kindBytes},
				{Number: 4, Name: "TranslatedPort", Kind: kindMessage, MessageType: "PortInfo"},
			}},
			{Name: "DeviceAuthorizationFlowRequest"},
			{Name: "DeviceAuthorizationFlow", Fields: []field{
				{Number: 1, Name: "Provider", Kind: kindEnum, EnumType: "DeviceAuthorizationFlowProvider"},
				{Number: 2, Name: "ProviderConfig", Kind: kindMessage, MessageType: "ProviderConfig"},
			}},
			{Name: "PKCEAuthorizationFlowRequest"},
			{Name: "PKCEAuthorizationFlow", Fields: []field{
				{Number: 1, Name: "ProviderConfig", Kind: kindMessage, MessageType: "ProviderConfig"},
			}},
			{Name: "ProviderConfig", Fields: []field{
				{Number: 1, Name: "ClientID", Kind: kindString},
				{Number: 2, Name: "ClientSecret", Kind: kindString},
				{Number: 3, Name: "Domain", Kind: kindString},
				{Number: 4, Name: "Audience", Kind: kindString},
				{Number: 5, Name: "DeviceAuthEndpoint", Kind: kindString},
				{Number: 6, Name: "TokenEndpoint", Kind: kindString},
				{Number: 7, Name: "Scope", Kind: kindString},
				{Number: 8, Name: "UseIDToken", Kind: kindBool},
				{Number: 9, Name: "AuthorizationEndpoint", Kind: kindString},
				{Number: 10, Name: "RedirectURLs", Kind: kindRepeatedString},
				{Number: 11, Name: "DisablePromptLogin", Kind: kindBool},
				{Number: 12, Name: "LoginFlag", Kind: kindUint32},
			}},
			{Name: "ExposeServiceRequest", Fields: []field{
				{Number: 1, Name: "Port", Kind: kindUint32},
				{Number: 2, Name: "Protocol", Kind: kindEnum, EnumType: "ExposeProtocol"},
				{Number: 3, Name: "Pin", Kind: kindString},
				{Number: 4, Name: "Password", Kind: kindString},
				{Number: 5, Name: "UserGroups", Kind: kindRepeatedString},
				{Number: 6, Name: "Domain", Kind: kindString},
				{Number: 7, Name: "NamePrefix", Kind: kindString},
				{Number: 8, Name: "ListenPort", Kind: kindUint32},
			}},
			{Name: "ExposeServiceResponse", Fields: []field{
				{Number: 1, Name: "ServiceName", Kind: kindString},
				{Number: 2, Name: "ServiceUrl", Kind: kindString},
				{Number: 3, Name: "Domain", Kind: kindString},
				{Number: 4, Name: "PortAutoAssigned", Kind: kindBool},
			}},
			{Name: "RenewExposeRequest", Fields: []field{
				{Number: 1, Name: "Domain", Kind: kindString},
			}},
			{Name: "RenewExposeResponse"},
			{Name: "StopExposeRequest", Fields: []field{
				{Number: 1, Name: "Domain", Kind: kindString},
			}},
			{Name: "StopExposeResponse"},
		},
	},
	"flow": {
		Name:      "flow",
		Package:   "proto",
		Canary:    "flow proto fast-path",
		Prefix:    "flow",
		OutputDir: "flow/proto",
		PBFile:    "flow.pb.go",
		Messages: []message{
			{Name: "FlowEvent", Fields: []field{
				{Number: 1, Name: "EventId", Kind: kindBytes},
				{Number: 2, Name: "Timestamp", Kind: kindTimestamp},
				{Number: 3, Name: "PublicKey", Kind: kindBytes},
				{Number: 4, Name: "FlowFields", Kind: kindMessage, MessageType: "FlowFields"},
				{Number: 5, Name: "IsInitiator", Kind: kindBool},
			}},
			{Name: "FlowEventAck", Fields: []field{
				{Number: 1, Name: "EventId", Kind: kindBytes},
				{Number: 2, Name: "IsInitiator", Kind: kindBool},
			}},
			{Name: "FlowFields", Fields: []field{
				{Number: 1, Name: "FlowId", Kind: kindBytes},
				{Number: 2, Name: "Type", Kind: kindEnum, EnumType: "Type"},
				{Number: 3, Name: "RuleId", Kind: kindBytes},
				{Number: 4, Name: "Direction", Kind: kindEnum, EnumType: "Direction"},
				{Number: 5, Name: "Protocol", Kind: kindUint32},
				{Number: 6, Name: "SourceIp", Kind: kindBytes},
				{Number: 7, Name: "DestIp", Kind: kindBytes},
				{Number: 0, Name: "ConnectionInfo", Kind: kindFlowFieldsOneof},
				{Number: 10, Name: "RxPackets", Kind: kindUint64},
				{Number: 11, Name: "TxPackets", Kind: kindUint64},
				{Number: 12, Name: "RxBytes", Kind: kindUint64},
				{Number: 13, Name: "TxBytes", Kind: kindUint64},
				{Number: 14, Name: "SourceResourceId", Kind: kindBytes},
				{Number: 15, Name: "DestResourceId", Kind: kindBytes},
			}},
			{Name: "PortInfo", Fields: []field{
				{Number: 1, Name: "SourcePort", Kind: kindUint32},
				{Number: 2, Name: "DestPort", Kind: kindUint32},
			}},
			{Name: "ICMPInfo", Fields: []field{
				{Number: 1, Name: "IcmpType", Kind: kindUint32},
				{Number: 2, Name: "IcmpCode", Kind: kindUint32},
			}},
		},
	},
	"proxy_service": {
		Name:                "proxy_service",
		Package:             "proto",
		Canary:              "proxy service proto fast-path",
		Prefix:              "proxy_service",
		OutputDir:           "shared/management/proto",
		PBFile:              "proxy_service.pb.go",
		ReusePackageHelpers: true,
		Messages: []message{
			{Name: "ProxyCapabilities", Fields: []field{
				{Number: 1, Name: "SupportsCustomPorts", Kind: kindOptionalBool},
				{Number: 2, Name: "RequireSubdomain", Kind: kindOptionalBool},
				{Number: 3, Name: "SupportsCrowdsec", Kind: kindOptionalBool},
				{Number: 4, Name: "Private", Kind: kindOptionalBool},
				{Number: 5, Name: "SupportsPrivateService", Kind: kindOptionalBool},
			}},
			{Name: "GetMappingUpdateRequest", Fields: []field{
				{Number: 1, Name: "ProxyId", Kind: kindString},
				{Number: 2, Name: "Version", Kind: kindString},
				{Number: 3, Name: "StartedAt", Kind: kindTimestamp},
				{Number: 4, Name: "Address", Kind: kindString},
				{Number: 5, Name: "Capabilities", Kind: kindMessage, MessageType: "ProxyCapabilities"},
			}},
			{Name: "GetMappingUpdateResponse", Fields: []field{
				{Number: 1, Name: "Mapping", Kind: kindRepeatedMsg, MessageType: "ProxyMapping"},
				{Number: 2, Name: "InitialSyncComplete", Kind: kindBool},
			}},
			{Name: "PathTargetOptions", Fields: []field{
				{Number: 1, Name: "SkipTlsVerify", Kind: kindBool},
				{Number: 2, Name: "RequestTimeout", Kind: kindDuration},
				{Number: 3, Name: "PathRewrite", Kind: kindEnum, EnumType: "PathRewriteMode"},
				{Number: 4, Name: "CustomHeaders", Kind: kindMapStringString},
				{Number: 5, Name: "ProxyProtocol", Kind: kindBool},
				{Number: 6, Name: "SessionIdleTimeout", Kind: kindDuration},
				{Number: 7, Name: "DirectUpstream", Kind: kindBool},
			}},
			{Name: "PathMapping", Fields: []field{
				{Number: 1, Name: "Path", Kind: kindString},
				{Number: 2, Name: "Target", Kind: kindString},
				{Number: 3, Name: "Options", Kind: kindMessage, MessageType: "PathTargetOptions"},
			}},
			{Name: "HeaderAuth", Fields: []field{
				{Number: 1, Name: "Header", Kind: kindString},
				{Number: 2, Name: "HashedValue", Kind: kindString},
			}},
			{Name: "Authentication", Fields: []field{
				{Number: 1, Name: "SessionKey", Kind: kindString},
				{Number: 2, Name: "MaxSessionAgeSeconds", Kind: kindInt64},
				{Number: 3, Name: "Password", Kind: kindBool},
				{Number: 4, Name: "Pin", Kind: kindBool},
				{Number: 5, Name: "Oidc", Kind: kindBool},
				{Number: 6, Name: "HeaderAuths", Kind: kindRepeatedMsg, MessageType: "HeaderAuth"},
			}},
			{Name: "AccessRestrictions", Fields: []field{
				{Number: 1, Name: "AllowedCidrs", Kind: kindRepeatedString},
				{Number: 2, Name: "BlockedCidrs", Kind: kindRepeatedString},
				{Number: 3, Name: "AllowedCountries", Kind: kindRepeatedString},
				{Number: 4, Name: "BlockedCountries", Kind: kindRepeatedString},
				{Number: 5, Name: "CrowdsecMode", Kind: kindString},
			}},
			{Name: "ProxyMapping", Fields: []field{
				{Number: 1, Name: "Type", Kind: kindEnum, EnumType: "ProxyMappingUpdateType"},
				{Number: 2, Name: "Id", Kind: kindString},
				{Number: 3, Name: "AccountId", Kind: kindString},
				{Number: 4, Name: "Domain", Kind: kindString},
				{Number: 5, Name: "Path", Kind: kindRepeatedMsg, MessageType: "PathMapping"},
				{Number: 6, Name: "AuthToken", Kind: kindString},
				{Number: 7, Name: "Auth", Kind: kindMessage, MessageType: "Authentication"},
				{Number: 8, Name: "PassHostHeader", Kind: kindBool},
				{Number: 9, Name: "RewriteRedirects", Kind: kindBool},
				{Number: 10, Name: "Mode", Kind: kindString},
				{Number: 11, Name: "ListenPort", Kind: kindInt32},
				{Number: 12, Name: "AccessRestrictions", Kind: kindMessage, MessageType: "AccessRestrictions"},
				{Number: 13, Name: "Private", Kind: kindBool},
			}},
			{Name: "SendAccessLogRequest", Fields: []field{
				{Number: 1, Name: "Log", Kind: kindMessage, MessageType: "AccessLog"},
			}},
			{Name: "SendAccessLogResponse"},
			{Name: "AccessLog", Fields: []field{
				{Number: 1, Name: "Timestamp", Kind: kindTimestamp},
				{Number: 2, Name: "LogId", Kind: kindString},
				{Number: 3, Name: "AccountId", Kind: kindString},
				{Number: 4, Name: "ServiceId", Kind: kindString},
				{Number: 5, Name: "Host", Kind: kindString},
				{Number: 6, Name: "Path", Kind: kindString},
				{Number: 7, Name: "DurationMs", Kind: kindInt64},
				{Number: 8, Name: "Method", Kind: kindString},
				{Number: 9, Name: "ResponseCode", Kind: kindInt32},
				{Number: 10, Name: "SourceIp", Kind: kindString},
				{Number: 11, Name: "AuthMechanism", Kind: kindString},
				{Number: 12, Name: "UserId", Kind: kindString},
				{Number: 13, Name: "AuthSuccess", Kind: kindBool},
				{Number: 14, Name: "BytesUpload", Kind: kindInt64},
				{Number: 15, Name: "BytesDownload", Kind: kindInt64},
				{Number: 16, Name: "Protocol", Kind: kindString},
				{Number: 17, Name: "Metadata", Kind: kindMapStringString},
			}},
			{Name: "AuthenticateRequest", Fields: []field{
				{Number: 1, Name: "Id", Kind: kindString},
				{Number: 2, Name: "AccountId", Kind: kindString},
				{Number: 0, Name: "Request", Kind: kindAuthReqOneof},
			}},
			{Name: "HeaderAuthRequest", Fields: []field{
				{Number: 1, Name: "HeaderValue", Kind: kindString},
				{Number: 2, Name: "HeaderName", Kind: kindString},
			}},
			{Name: "PasswordRequest", Fields: []field{
				{Number: 1, Name: "Password", Kind: kindString},
			}},
			{Name: "PinRequest", Fields: []field{
				{Number: 1, Name: "Pin", Kind: kindString},
			}},
			{Name: "AuthenticateResponse", Fields: []field{
				{Number: 1, Name: "Success", Kind: kindBool},
				{Number: 2, Name: "SessionToken", Kind: kindString},
			}},
			{Name: "SendStatusUpdateRequest", Fields: []field{
				{Number: 1, Name: "ServiceId", Kind: kindString},
				{Number: 2, Name: "AccountId", Kind: kindString},
				{Number: 3, Name: "Status", Kind: kindEnum, EnumType: "ProxyStatus"},
				{Number: 4, Name: "CertificateIssued", Kind: kindBool},
				{Number: 5, Name: "ErrorMessage", Kind: kindOptionalString},
				{Number: 50, Name: "InboundListener", Kind: kindMessage, MessageType: "ProxyInboundListener"},
			}},
			{Name: "ProxyInboundListener", Fields: []field{
				{Number: 1, Name: "TunnelIp", Kind: kindString},
				{Number: 2, Name: "HttpsPort", Kind: kindUint32},
				{Number: 3, Name: "HttpPort", Kind: kindUint32},
			}},
			{Name: "SendStatusUpdateResponse"},
			{Name: "CreateProxyPeerRequest", Fields: []field{
				{Number: 1, Name: "ServiceId", Kind: kindString},
				{Number: 2, Name: "AccountId", Kind: kindString},
				{Number: 3, Name: "Token", Kind: kindString},
				{Number: 4, Name: "WireguardPublicKey", Kind: kindString},
				{Number: 5, Name: "Cluster", Kind: kindString},
			}},
			{Name: "CreateProxyPeerResponse", Fields: []field{
				{Number: 1, Name: "Success", Kind: kindBool},
				{Number: 2, Name: "ErrorMessage", Kind: kindOptionalString},
			}},
			{Name: "GetOIDCURLRequest", Fields: []field{
				{Number: 1, Name: "Id", Kind: kindString},
				{Number: 2, Name: "AccountId", Kind: kindString},
				{Number: 3, Name: "RedirectUrl", Kind: kindString},
			}},
			{Name: "GetOIDCURLResponse", Fields: []field{
				{Number: 1, Name: "Url", Kind: kindString},
			}},
			{Name: "ValidateSessionRequest", Fields: []field{
				{Number: 1, Name: "Domain", Kind: kindString},
				{Number: 2, Name: "SessionToken", Kind: kindString},
			}},
			{Name: "ValidateSessionResponse", Fields: []field{
				{Number: 1, Name: "Valid", Kind: kindBool},
				{Number: 2, Name: "UserId", Kind: kindString},
				{Number: 3, Name: "UserEmail", Kind: kindString},
				{Number: 4, Name: "DeniedReason", Kind: kindString},
				{Number: 5, Name: "PeerGroupIds", Kind: kindRepeatedString},
				{Number: 6, Name: "PeerGroupNames", Kind: kindRepeatedString},
			}},
			{Name: "ValidateTunnelPeerRequest", Fields: []field{
				{Number: 1, Name: "TunnelIp", Kind: kindString},
				{Number: 2, Name: "Domain", Kind: kindString},
			}},
			{Name: "ValidateTunnelPeerResponse", Fields: []field{
				{Number: 1, Name: "Valid", Kind: kindBool},
				{Number: 2, Name: "UserId", Kind: kindString},
				{Number: 3, Name: "UserEmail", Kind: kindString},
				{Number: 4, Name: "DeniedReason", Kind: kindString},
				{Number: 5, Name: "SessionToken", Kind: kindString},
				{Number: 6, Name: "PeerGroupIds", Kind: kindRepeatedString},
				{Number: 7, Name: "PeerGroupNames", Kind: kindRepeatedString},
			}},
			{Name: "SyncMappingsRequest", Fields: []field{
				{Number: 0, Name: "Msg", Kind: kindSyncMapReqOneof},
			}},
			{Name: "SyncMappingsInit", Fields: []field{
				{Number: 1, Name: "ProxyId", Kind: kindString},
				{Number: 2, Name: "Version", Kind: kindString},
				{Number: 3, Name: "StartedAt", Kind: kindTimestamp},
				{Number: 4, Name: "Address", Kind: kindString},
				{Number: 5, Name: "Capabilities", Kind: kindMessage, MessageType: "ProxyCapabilities"},
			}},
			{Name: "SyncMappingsAck"},
			{Name: "SyncMappingsResponse", Fields: []field{
				{Number: 1, Name: "Mapping", Kind: kindRepeatedMsg, MessageType: "ProxyMapping"},
				{Number: 2, Name: "InitialSyncComplete", Kind: kindBool},
			}},
		},
	},
}

var targetOrder = []string{
	"signal",
	"management",
	"proxy_service",
	"flow",
}

func main() {
	var targetNames string
	var repoRoot string
	flag.StringVar(&targetNames, "target", "", "target proto package to generate: signal, management, proxy_service, flow, all, or a comma-separated list")
	flag.StringVar(&repoRoot, "repo-root", ".", "repository root")
	flag.Parse()

	selected := parseTargets(targetNames)
	for _, t := range selected {
		generateTarget(repoRoot, t)
	}
}

func parseTargets(targetNames string) []target {
	if targetNames == "" {
		failf("missing required -target")
	}
	names := strings.Split(targetNames, ",")
	var selected []target
	seen := make(map[string]bool)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if name == "all" {
			for _, orderedName := range targetOrder {
				if seen[orderedName] {
					continue
				}
				selected = append(selected, targets[orderedName])
				seen[orderedName] = true
			}
			continue
		}
		t, ok := targets[name]
		if !ok {
			failf("unknown -target %q", name)
		}
		if seen[name] {
			continue
		}
		selected = append(selected, t)
		seen[name] = true
	}
	if len(selected) == 0 {
		failf("no targets selected")
	}
	return selected
}

func generateTarget(repoRoot string, t target) {
	outDir := filepath.Join(repoRoot, t.OutputDir)
	writeGo(filepath.Join(outDir, t.Prefix+"_fastpath_default.go"), generateDefault(t))
	writeGo(filepath.Join(outDir, t.Prefix+"_fastpath_tinygo.go"), generateTinyGoHook(t))
	writeGo(filepath.Join(outDir, t.Prefix+"_fastpath_methods_tinygo.go"), generateMethods(t))
	patchPBGo(filepath.Join(outDir, t.PBFile), t)
}

func writeGo(path string, src []byte) {
	formatted, err := format.Source(src)
	if err != nil {
		failf("format %s: %v\n%s", path, err, src)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		failf("write %s: %v", path, err)
	}
}

func patchPBGo(path string, t target) {
	src, err := os.ReadFile(path)
	if err != nil {
		failf("read %s: %v", path, err)
	}
	out := string(src)
	for _, m := range t.Messages {
		sig := fmt.Sprintf("func (x *%s) ProtoReflect() protoreflect.Message {\n", m.Name)
		hook := fmt.Sprintf("\tif x != nil {\n\t\tif m := %sProtoReflect(x); m != nil {\n\t\t\treturn m\n\t\t}\n\t}\n", lower(m.Name))
		idx := strings.Index(out, sig)
		if idx < 0 {
			failf("could not find ProtoReflect method for %s in %s", m.Name, path)
		}
		bodyStart := idx + len(sig)
		bodySampleEnd := bodyStart + 512
		if bodySampleEnd > len(out) {
			bodySampleEnd = len(out)
		}
		if strings.Contains(out[bodyStart:bodySampleEnd], lower(m.Name)+"ProtoReflect(x)") {
			continue
		}
		out = out[:bodyStart] + hook + out[bodyStart:]
	}
	formatted, err := format.Source([]byte(out))
	if err != nil {
		failf("format %s after hook patch: %v", path, err)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		failf("write %s: %v", path, err)
	}
}

func generateDefault(t target) []byte {
	var b bytes.Buffer
	header(&b, t)
	fmt.Fprintln(&b, "//go:build !tinygo\n")
	fmt.Fprintf(&b, "package %s\n\n", t.Package)
	fmt.Fprintln(&b, `import "google.golang.org/protobuf/reflect/protoreflect"`)
	for _, m := range t.Messages {
		fmt.Fprintf(&b, "\nfunc %sProtoReflect(*%s) protoreflect.Message { return nil }\n", lower(m.Name), m.Name)
	}
	return b.Bytes()
}

func generateTinyGoHook(t target) []byte {
	var b bytes.Buffer
	header(&b, t)
	fmt.Fprintln(&b, "//go:build tinygo\n")
	fmt.Fprintf(&b, "package %s\n\n", t.Package)
	fmt.Fprintln(&b, `import "google.golang.org/protobuf/reflect/protoreflect"`)
	for _, m := range t.Messages {
		fmt.Fprintf(&b, "\nfunc %sProtoReflect(m *%s) protoreflect.Message {\n", lower(m.Name), m.Name)
		fmt.Fprintf(&b, "\treturn %sReflect{m: m}\n", lower(m.Name))
		fmt.Fprintln(&b, "}")
	}
	return b.Bytes()
}

func generateMethods(t target) []byte {
	var b bytes.Buffer
	header(&b, t)
	fmt.Fprintln(&b, "//go:build tinygo\n")
	fmt.Fprintf(&b, "package %s\n\n", t.Package)
	fmt.Fprintln(&b, "import (")
	fmt.Fprintln(&b, "\t\"bytes\"")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "\t\"google.golang.org/protobuf/encoding/protowire\"")
	fmt.Fprintln(&b, "\t\"google.golang.org/protobuf/reflect/protoreflect\"")
	fmt.Fprintln(&b, "\t\"google.golang.org/protobuf/runtime/protoiface\"")
	if hasKind(t, kindDuration) {
		fmt.Fprintln(&b, "\t\"google.golang.org/protobuf/types/known/durationpb\"")
	}
	if hasKind(t, kindTimestamp) {
		fmt.Fprintln(&b, "\t\"google.golang.org/protobuf/types/known/timestamppb\"")
	}
	fmt.Fprintln(&b, ")\n")

	for _, m := range t.Messages {
		fmt.Fprintf(&b, "type %sReflect struct{ m *%s }\n", lower(m.Name), m.Name)
	}
	if !t.ReusePackageHelpers {
		fmt.Fprintf(&b, "\nfunc protoCanary(method string) string { return %q + method }\n\n", t.Canary+": unexpected protoreflect.Message.")
	}
	for _, m := range t.Messages {
		emitReflect(&b, m)
	}
	for _, m := range t.Messages {
		emitMethods(&b, m)
	}
	for _, m := range t.Messages {
		emitSize(&b, m)
		emitMarshal(&b, m)
		emitUnmarshal(&b, m)
		emitMerge(&b, m)
		emitEqual(&b, m)
	}
	if hasKind(t, kindTimestamp) && !t.ReusePackageHelpers {
		emitWellKnown(&b, "Timestamp", "timestamppb.Timestamp")
	}
	if hasKind(t, kindDuration) && !t.ReusePackageHelpers {
		emitWellKnown(&b, "Duration", "durationpb.Duration")
	}
	emitMapHelpers(&b, t)
	if hasKind(t, kindPortInfoOneof) {
		emitPortInfoSelectionHelpers(&b)
	}
	if hasKind(t, kindJobReqOneof) {
		emitJobRequestWorkloadHelpers(&b)
	}
	if hasKind(t, kindJobRespOneof) {
		emitJobResponseWorkloadHelpers(&b)
	}
	if hasKind(t, kindFlowFieldsOneof) {
		emitFlowFieldsConnectionInfoHelpers(&b)
	}
	if hasKind(t, kindAuthReqOneof) {
		emitAuthenticateRequestHelpers(&b)
	}
	if hasKind(t, kindSyncMapReqOneof) {
		emitSyncMappingsRequestHelpers(&b)
	}
	return b.Bytes()
}

func header(b *bytes.Buffer, t target) {
	fmt.Fprintf(b, "// Code generated by go run ./tools/protoc-gen-go-netbird-tinygo -target %s; DO NOT EDIT.\n\n", t.Name)
}

func emitReflect(b *bytes.Buffer, m message) {
	w := lower(m.Name) + "Reflect"
	methods := lower(m.Name) + "Methods"
	fmt.Fprintf(b, "func (r %s) Descriptor() protoreflect.MessageDescriptor { panic(protoCanary(\"Descriptor\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) Type() protoreflect.MessageType { panic(protoCanary(\"Type\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) New() protoreflect.Message { return %s{m: new(%s)} }\n", w, w, m.Name)
	fmt.Fprintf(b, "func (r %s) Interface() protoreflect.ProtoMessage { return r.m }\n", w)
	fmt.Fprintf(b, "func (r %s) Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool) { panic(protoCanary(\"Range\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) Has(protoreflect.FieldDescriptor) bool { panic(protoCanary(\"Has\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) Clear(protoreflect.FieldDescriptor) { panic(protoCanary(\"Clear\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) Get(protoreflect.FieldDescriptor) protoreflect.Value { panic(protoCanary(\"Get\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) Set(protoreflect.FieldDescriptor, protoreflect.Value) { panic(protoCanary(\"Set\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) Mutable(protoreflect.FieldDescriptor) protoreflect.Value { panic(protoCanary(\"Mutable\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) NewField(protoreflect.FieldDescriptor) protoreflect.Value { panic(protoCanary(\"NewField\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) WhichOneof(protoreflect.OneofDescriptor) protoreflect.FieldDescriptor { panic(protoCanary(\"WhichOneof\")) }\n", w)
	fmt.Fprintf(b, "func (r %s) GetUnknown() protoreflect.RawFields { return r.m.unknownFields }\n", w)
	fmt.Fprintf(b, "func (r %s) SetUnknown(f protoreflect.RawFields) { r.m.unknownFields = append(r.m.unknownFields[:0], f...) }\n", w)
	fmt.Fprintf(b, "func (r %s) IsValid() bool { return r.m != nil }\n", w)
	fmt.Fprintf(b, "func (r %s) ProtoMethods() *protoiface.Methods { return &%s }\n\n", w, methods)
}

func emitMethods(b *bytes.Buffer, m message) {
	l := lower(m.Name)
	w := l + "Reflect"
	fmt.Fprintf(b, "var %sMethods = protoiface.Methods{\n", l)
	fmt.Fprintln(b, "\tFlags: protoiface.SupportMarshalDeterministic | protoiface.SupportUnmarshalDiscardUnknown,")
	fmt.Fprintf(b, "\tSize: func(in protoiface.SizeInput) protoiface.SizeOutput { return protoiface.SizeOutput{Size: size%s(in.Message.(%s).m)} },\n", m.Name, w)
	fmt.Fprintf(b, "\tMarshal: func(in protoiface.MarshalInput) (protoiface.MarshalOutput, error) { return protoiface.MarshalOutput{Buf: marshal%s(in.Buf, in.Message.(%s).m)}, nil },\n", m.Name, w)
	fmt.Fprintf(b, "\tUnmarshal: func(in protoiface.UnmarshalInput) (protoiface.UnmarshalOutput, error) { err := unmarshal%s(in.Message.(%s).m, in.Buf); return protoiface.UnmarshalOutput{Flags: protoiface.UnmarshalInitialized}, err },\n", m.Name, w)
	fmt.Fprintf(b, "\tMerge: func(in protoiface.MergeInput) protoiface.MergeOutput { merge%s(in.Destination.(%s).m, in.Source.(%s).m); return protoiface.MergeOutput{Flags: protoiface.MergeComplete} },\n", m.Name, w, w)
	fmt.Fprintln(b, "\tCheckInitialized: func(protoiface.CheckInitializedInput) (protoiface.CheckInitializedOutput, error) { return protoiface.CheckInitializedOutput{}, nil },")
	fmt.Fprintf(b, "\tEqual: func(in protoiface.EqualInput) protoiface.EqualOutput { return protoiface.EqualOutput{Equal: equal%s(in.MessageA.(%s).m, in.MessageB.(%s).m)} },\n", m.Name, w, w)
	fmt.Fprintln(b, "}\n")
}

func emitSize(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func size%s(m *%s) int {\n\tn := 0\n", m.Name, m.Name)
	for _, f := range m.Fields {
		switch f.Kind {
		case kindString:
			fmt.Fprintf(b, "\tif m.%s != \"\" { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindBytes:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindBool:
			fmt.Fprintf(b, "\tif m.%s { n += protowire.SizeTag(%d) + protowire.SizeVarint(protowire.EncodeBool(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindInt32, kindInt64, kindUint32, kindUint64, kindEnum:
			fmt.Fprintf(b, "\tif m.%s != 0 { n += protowire.SizeTag(%d) + protowire.SizeVarint(uint64(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif m.%s != nil { s := size%s(m.%s); n += protowire.SizeTag(%d) + protowire.SizeBytes(s) }\n", f.Name, f.MessageType, f.Name, f.Number)
		case kindTimestamp:
			fmt.Fprintf(b, "\tif m.%s != nil { s := sizeTimestamp(m.%s); n += protowire.SizeTag(%d) + protowire.SizeBytes(s) }\n", f.Name, f.Name, f.Number)
		case kindDuration:
			fmt.Fprintf(b, "\tif m.%s != nil { s := sizeDuration(m.%s); n += protowire.SizeTag(%d) + protowire.SizeBytes(s) }\n", f.Name, f.Name, f.Number)
		case kindRepeatedUint32:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { packed := 0; for _, v := range m.%s { packed += protowire.SizeVarint(uint64(v)) }; n += protowire.SizeTag(%d) + protowire.SizeBytes(packed) }\n", f.Name, f.Name, f.Number)
		case kindRepeatedEnum:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { packed := 0; for _, v := range m.%s { packed += protowire.SizeVarint(uint64(v)) }; n += protowire.SizeTag(%d) + protowire.SizeBytes(packed) }\n", f.Name, f.Name, f.Number)
		case kindRepeatedString:
			fmt.Fprintf(b, "\tfor _, v := range m.%s { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(v)) }\n", f.Name, f.Number)
		case kindRepeatedBytes:
			fmt.Fprintf(b, "\tfor _, v := range m.%s { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(v)) }\n", f.Name, f.Number)
		case kindRepeatedMsg:
			fmt.Fprintf(b, "\tfor _, v := range m.%s { if v != nil { s := size%s(v); n += protowire.SizeTag(%d) + protowire.SizeBytes(s) } }\n", f.Name, f.MessageType, f.Number)
		case kindMapStringMsg:
			fmt.Fprintf(b, "\tfor k, v := range m.%s { entry := protowire.SizeTag(1) + protowire.SizeBytes(len(k)); if v != nil { s := size%s(v); entry += protowire.SizeTag(2) + protowire.SizeBytes(s) }; n += protowire.SizeTag(%d) + protowire.SizeBytes(entry) }\n", f.Name, f.MessageType, f.Number)
		case kindMapStringString:
			fmt.Fprintf(b, "\tfor k, v := range m.%s { entry := protowire.SizeTag(1) + protowire.SizeBytes(len(k)) + protowire.SizeTag(2) + protowire.SizeBytes(len(v)); n += protowire.SizeTag(%d) + protowire.SizeBytes(entry) }\n", f.Name, f.Number)
		case kindPortInfoOneof:
			fmt.Fprintln(b, "\tif v, ok := m.PortSelection.(*PortInfo_Port); ok { n += protowire.SizeTag(1) + protowire.SizeVarint(uint64(v.Port)) }")
			fmt.Fprintln(b, "\tif v, ok := m.PortSelection.(*PortInfo_Range_); ok && v.Range != nil { s := sizePortInfo_Range(v.Range); n += protowire.SizeTag(2) + protowire.SizeBytes(s) }")
		case kindJobReqOneof:
			fmt.Fprintln(b, "\tif v, ok := m.WorkloadParameters.(*JobRequest_Bundle); ok && v.Bundle != nil { s := sizeBundleParameters(v.Bundle); n += protowire.SizeTag(10) + protowire.SizeBytes(s) }")
		case kindJobRespOneof:
			fmt.Fprintln(b, "\tif v, ok := m.WorkloadResults.(*JobResponse_Bundle); ok && v.Bundle != nil { s := sizeBundleResult(v.Bundle); n += protowire.SizeTag(10) + protowire.SizeBytes(s) }")
		case kindFlowFieldsOneof:
			fmt.Fprintln(b, "\tif v, ok := m.ConnectionInfo.(*FlowFields_PortInfo); ok && v.PortInfo != nil { s := sizePortInfo(v.PortInfo); n += protowire.SizeTag(8) + protowire.SizeBytes(s) }")
			fmt.Fprintln(b, "\tif v, ok := m.ConnectionInfo.(*FlowFields_IcmpInfo); ok && v.IcmpInfo != nil { s := sizeICMPInfo(v.IcmpInfo); n += protowire.SizeTag(9) + protowire.SizeBytes(s) }")
		case kindAuthReqOneof:
			fmt.Fprintln(b, "\tif v, ok := m.Request.(*AuthenticateRequest_Password); ok && v.Password != nil { s := sizePasswordRequest(v.Password); n += protowire.SizeTag(3) + protowire.SizeBytes(s) }")
			fmt.Fprintln(b, "\tif v, ok := m.Request.(*AuthenticateRequest_Pin); ok && v.Pin != nil { s := sizePinRequest(v.Pin); n += protowire.SizeTag(4) + protowire.SizeBytes(s) }")
			fmt.Fprintln(b, "\tif v, ok := m.Request.(*AuthenticateRequest_HeaderAuth); ok && v.HeaderAuth != nil { s := sizeHeaderAuthRequest(v.HeaderAuth); n += protowire.SizeTag(5) + protowire.SizeBytes(s) }")
		case kindSyncMapReqOneof:
			fmt.Fprintln(b, "\tif v, ok := m.Msg.(*SyncMappingsRequest_Init); ok && v.Init != nil { s := sizeSyncMappingsInit(v.Init); n += protowire.SizeTag(1) + protowire.SizeBytes(s) }")
			fmt.Fprintln(b, "\tif v, ok := m.Msg.(*SyncMappingsRequest_Ack); ok && v.Ack != nil { s := sizeSyncMappingsAck(v.Ack); n += protowire.SizeTag(2) + protowire.SizeBytes(s) }")
		case kindOptionalString:
			fmt.Fprintf(b, "\tif m.%s != nil { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(*m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif m.%s != nil { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBool:
			fmt.Fprintf(b, "\tif m.%s != nil { n += protowire.SizeTag(%d) + protowire.SizeVarint(protowire.EncodeBool(*m.%s)) }\n", f.Name, f.Number, f.Name)
		}
	}
	fmt.Fprintln(b, "\tn += len(m.unknownFields)")
	fmt.Fprintln(b, "\treturn n\n}\n")
}

func emitMarshal(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func marshal%s(b []byte, m *%s) []byte {\n", m.Name, m.Name)
	for _, f := range m.Fields {
		switch f.Kind {
		case kindString:
			fmt.Fprintf(b, "\tif m.%s != \"\" { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendString(b, m.%s) }\n", f.Name, f.Number, f.Name)
		case kindBytes:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendBytes(b, m.%s) }\n", f.Name, f.Number, f.Name)
		case kindBool:
			fmt.Fprintf(b, "\tif m.%s { b = protowire.AppendTag(b, %d, protowire.VarintType); b = protowire.AppendVarint(b, protowire.EncodeBool(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindInt32, kindInt64, kindUint32, kindUint64, kindEnum:
			fmt.Fprintf(b, "\tif m.%s != 0 { b = protowire.AppendTag(b, %d, protowire.VarintType); b = protowire.AppendVarint(b, uint64(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(size%s(m.%s))); b = marshal%s(b, m.%s) }\n", f.Name, f.Number, f.MessageType, f.Name, f.MessageType, f.Name)
		case kindTimestamp:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeTimestamp(m.%s))); b = marshalTimestamp(b, m.%s) }\n", f.Name, f.Number, f.Name, f.Name)
		case kindDuration:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeDuration(m.%s))); b = marshalDuration(b, m.%s) }\n", f.Name, f.Number, f.Name, f.Name)
		case kindRepeatedUint32:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { packed := 0; for _, v := range m.%s { packed += protowire.SizeVarint(uint64(v)) }; b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(packed)); for _, v := range m.%s { b = protowire.AppendVarint(b, uint64(v)) } }\n", f.Name, f.Name, f.Number, f.Name)
		case kindRepeatedEnum:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { packed := 0; for _, v := range m.%s { packed += protowire.SizeVarint(uint64(v)) }; b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(packed)); for _, v := range m.%s { b = protowire.AppendVarint(b, uint64(v)) } }\n", f.Name, f.Name, f.Number, f.Name)
		case kindRepeatedString:
			fmt.Fprintf(b, "\tfor _, v := range m.%s { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendString(b, v) }\n", f.Name, f.Number)
		case kindRepeatedBytes:
			fmt.Fprintf(b, "\tfor _, v := range m.%s { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendBytes(b, v) }\n", f.Name, f.Number)
		case kindRepeatedMsg:
			fmt.Fprintf(b, "\tfor _, v := range m.%s { if v != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(size%s(v))); b = marshal%s(b, v) } }\n", f.Name, f.Number, f.MessageType, f.MessageType)
		case kindMapStringMsg:
			fmt.Fprintf(b, "\tfor k, v := range m.%s { entry := protowire.SizeTag(1) + protowire.SizeBytes(len(k)); if v != nil { s := size%s(v); entry += protowire.SizeTag(2) + protowire.SizeBytes(s) }; b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(entry)); b = protowire.AppendTag(b, 1, protowire.BytesType); b = protowire.AppendString(b, k); if v != nil { b = protowire.AppendTag(b, 2, protowire.BytesType); b = protowire.AppendVarint(b, uint64(size%s(v))); b = marshal%s(b, v) } }\n", f.Name, f.MessageType, f.Number, f.MessageType, f.MessageType)
		case kindMapStringString:
			fmt.Fprintf(b, "\tfor k, v := range m.%s { entry := protowire.SizeTag(1) + protowire.SizeBytes(len(k)) + protowire.SizeTag(2) + protowire.SizeBytes(len(v)); b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(entry)); b = protowire.AppendTag(b, 1, protowire.BytesType); b = protowire.AppendString(b, k); b = protowire.AppendTag(b, 2, protowire.BytesType); b = protowire.AppendString(b, v) }\n", f.Name, f.Number)
		case kindPortInfoOneof:
			fmt.Fprintln(b, "\tif v, ok := m.PortSelection.(*PortInfo_Port); ok { b = protowire.AppendTag(b, 1, protowire.VarintType); b = protowire.AppendVarint(b, uint64(v.Port)) }")
			fmt.Fprintln(b, "\tif v, ok := m.PortSelection.(*PortInfo_Range_); ok && v.Range != nil { b = protowire.AppendTag(b, 2, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizePortInfo_Range(v.Range))); b = marshalPortInfo_Range(b, v.Range) }")
		case kindJobReqOneof:
			fmt.Fprintln(b, "\tif v, ok := m.WorkloadParameters.(*JobRequest_Bundle); ok && v.Bundle != nil { b = protowire.AppendTag(b, 10, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeBundleParameters(v.Bundle))); b = marshalBundleParameters(b, v.Bundle) }")
		case kindJobRespOneof:
			fmt.Fprintln(b, "\tif v, ok := m.WorkloadResults.(*JobResponse_Bundle); ok && v.Bundle != nil { b = protowire.AppendTag(b, 10, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeBundleResult(v.Bundle))); b = marshalBundleResult(b, v.Bundle) }")
		case kindFlowFieldsOneof:
			fmt.Fprintln(b, "\tif v, ok := m.ConnectionInfo.(*FlowFields_PortInfo); ok && v.PortInfo != nil { b = protowire.AppendTag(b, 8, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizePortInfo(v.PortInfo))); b = marshalPortInfo(b, v.PortInfo) }")
			fmt.Fprintln(b, "\tif v, ok := m.ConnectionInfo.(*FlowFields_IcmpInfo); ok && v.IcmpInfo != nil { b = protowire.AppendTag(b, 9, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeICMPInfo(v.IcmpInfo))); b = marshalICMPInfo(b, v.IcmpInfo) }")
		case kindAuthReqOneof:
			fmt.Fprintln(b, "\tif v, ok := m.Request.(*AuthenticateRequest_Password); ok && v.Password != nil { b = protowire.AppendTag(b, 3, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizePasswordRequest(v.Password))); b = marshalPasswordRequest(b, v.Password) }")
			fmt.Fprintln(b, "\tif v, ok := m.Request.(*AuthenticateRequest_Pin); ok && v.Pin != nil { b = protowire.AppendTag(b, 4, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizePinRequest(v.Pin))); b = marshalPinRequest(b, v.Pin) }")
			fmt.Fprintln(b, "\tif v, ok := m.Request.(*AuthenticateRequest_HeaderAuth); ok && v.HeaderAuth != nil { b = protowire.AppendTag(b, 5, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeHeaderAuthRequest(v.HeaderAuth))); b = marshalHeaderAuthRequest(b, v.HeaderAuth) }")
		case kindSyncMapReqOneof:
			fmt.Fprintln(b, "\tif v, ok := m.Msg.(*SyncMappingsRequest_Init); ok && v.Init != nil { b = protowire.AppendTag(b, 1, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeSyncMappingsInit(v.Init))); b = marshalSyncMappingsInit(b, v.Init) }")
			fmt.Fprintln(b, "\tif v, ok := m.Msg.(*SyncMappingsRequest_Ack); ok && v.Ack != nil { b = protowire.AppendTag(b, 2, protowire.BytesType); b = protowire.AppendVarint(b, uint64(sizeSyncMappingsAck(v.Ack))); b = marshalSyncMappingsAck(b, v.Ack) }")
		case kindOptionalString:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendString(b, *m.%s) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendBytes(b, m.%s) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBool:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.VarintType); b = protowire.AppendVarint(b, protowire.EncodeBool(*m.%s)) }\n", f.Name, f.Number, f.Name)
		}
	}
	fmt.Fprintln(b, "\tb = append(b, m.unknownFields...)")
	fmt.Fprintln(b, "\treturn b\n}\n")
}

func emitUnmarshal(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func unmarshal%s(m *%s, b []byte) error {\n\t*m = %s{}\n\tfor len(b) > 0 {\n\t\tfieldStart := b\n\t\tnum, typ, n := protowire.ConsumeTag(b)\n\t\tif n < 0 { return protowire.ParseError(n) }\n\t\tb = b[n:]\n\t\tswitch {\n", m.Name, m.Name, m.Name)
	for _, f := range m.Fields {
		emitUnmarshalCase(b, f)
	}
	fmt.Fprintln(b, "\t\tdefault:")
	fmt.Fprintln(b, "\t\t\tskip := protowire.ConsumeFieldValue(num, typ, b)")
	fmt.Fprintln(b, "\t\t\tif skip < 0 { return protowire.ParseError(skip) }")
	fmt.Fprintln(b, "\t\t\tm.unknownFields = append(m.unknownFields, fieldStart[:n+skip]...)")
	fmt.Fprintln(b, "\t\t\tb = b[skip:]")
	fmt.Fprintln(b, "\t\t}")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "\treturn nil\n}\n")
}

func emitUnmarshalCase(b *bytes.Buffer, f field) {
	switch f.Kind {
	case kindString:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeString(b); if n < 0 { return protowire.ParseError(n) }; m.%s = v; b = b[n:]\n", f.Number, f.Name)
	case kindBytes:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s[:0], v...); b = b[n:]\n", f.Number, f.Name, f.Name)
	case kindBool:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = protowire.DecodeBool(v); b = b[n:]\n", f.Number, f.Name)
	case kindInt32:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = int32(v); b = b[n:]\n", f.Number, f.Name)
	case kindInt64:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = int64(v); b = b[n:]\n", f.Number, f.Name)
	case kindUint32:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = uint32(v); b = b[n:]\n", f.Number, f.Name)
	case kindUint64:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = uint64(v); b = b[n:]\n", f.Number, f.Name)
	case kindEnum:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = %s(v); b = b[n:]\n", f.Number, f.Name, f.EnumType)
	case kindMessage:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; if m.%s == nil { m.%s = &%s{} }; if err := unmarshal%s(m.%s, v); err != nil { return err }; b = b[n:]\n", f.Number, f.Name, f.Name, f.MessageType, f.MessageType, f.Name)
	case kindTimestamp:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; m.%s = &timestamppb.Timestamp{}; if err := unmarshalTimestamp(m.%s, v); err != nil { return err }; b = b[n:]\n", f.Number, f.Name, f.Name)
	case kindDuration:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; m.%s = &durationpb.Duration{}; if err := unmarshalDuration(m.%s, v); err != nil { return err }; b = b[n:]\n", f.Number, f.Name, f.Name)
	case kindRepeatedUint32:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; for len(v) > 0 { item, consumed := protowire.ConsumeVarint(v); if consumed < 0 { return protowire.ParseError(consumed) }; m.%s = append(m.%s, uint32(item)); v = v[consumed:] }; b = b[n:]\n", f.Number, f.Name, f.Name)
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s, uint32(v)); b = b[n:]\n", f.Number, f.Name, f.Name)
	case kindRepeatedEnum:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; for len(v) > 0 { item, consumed := protowire.ConsumeVarint(v); if consumed < 0 { return protowire.ParseError(consumed) }; m.%s = append(m.%s, %s(item)); v = v[consumed:] }; b = b[n:]\n", f.Number, f.Name, f.Name, f.EnumType)
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s, %s(v)); b = b[n:]\n", f.Number, f.Name, f.Name, f.EnumType)
	case kindRepeatedString:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeString(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s, v); b = b[n:]\n", f.Number, f.Name, f.Name)
	case kindRepeatedBytes:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s, append([]byte(nil), v...)); b = b[n:]\n", f.Number, f.Name, f.Name)
	case kindRepeatedMsg:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &%s{}; if err := unmarshal%s(item, v); err != nil { return err }; m.%s = append(m.%s, item); b = b[n:]\n", f.Number, f.MessageType, f.MessageType, f.Name, f.Name)
	case kindMapStringMsg:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; k, val, err := consumeString%sEntry(v); if err != nil { return err }; if m.%s == nil { m.%s = make(map[string]*%s) }; m.%s[k] = val; b = b[n:]\n", f.Number, f.MessageType, f.Name, f.Name, f.MessageType, f.Name)
	case kindMapStringString:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; k, val, err := consumeStringStringEntry(v); if err != nil { return err }; if m.%s == nil { m.%s = make(map[string]string) }; m.%s[k] = val; b = b[n:]\n", f.Number, f.Name, f.Name, f.Name)
	case kindPortInfoOneof:
		fmt.Fprintln(b, "\t\tcase num == 1 && typ == protowire.VarintType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.PortSelection = &PortInfo_Port{Port: uint32(v)}; b = b[n:]")
		fmt.Fprintln(b, "\t\tcase num == 2 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; r := &PortInfo_Range{}; if err := unmarshalPortInfo_Range(r, v); err != nil { return err }; m.PortSelection = &PortInfo_Range_{Range: r}; b = b[n:]")
	case kindJobReqOneof:
		fmt.Fprintln(b, "\t\tcase num == 10 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &BundleParameters{}; if err := unmarshalBundleParameters(item, v); err != nil { return err }; m.WorkloadParameters = &JobRequest_Bundle{Bundle: item}; b = b[n:]")
	case kindJobRespOneof:
		fmt.Fprintln(b, "\t\tcase num == 10 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &BundleResult{}; if err := unmarshalBundleResult(item, v); err != nil { return err }; m.WorkloadResults = &JobResponse_Bundle{Bundle: item}; b = b[n:]")
	case kindFlowFieldsOneof:
		fmt.Fprintln(b, "\t\tcase num == 8 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &PortInfo{}; if err := unmarshalPortInfo(item, v); err != nil { return err }; m.ConnectionInfo = &FlowFields_PortInfo{PortInfo: item}; b = b[n:]")
		fmt.Fprintln(b, "\t\tcase num == 9 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &ICMPInfo{}; if err := unmarshalICMPInfo(item, v); err != nil { return err }; m.ConnectionInfo = &FlowFields_IcmpInfo{IcmpInfo: item}; b = b[n:]")
	case kindAuthReqOneof:
		fmt.Fprintln(b, "\t\tcase num == 3 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &PasswordRequest{}; if err := unmarshalPasswordRequest(item, v); err != nil { return err }; m.Request = &AuthenticateRequest_Password{Password: item}; b = b[n:]")
		fmt.Fprintln(b, "\t\tcase num == 4 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &PinRequest{}; if err := unmarshalPinRequest(item, v); err != nil { return err }; m.Request = &AuthenticateRequest_Pin{Pin: item}; b = b[n:]")
		fmt.Fprintln(b, "\t\tcase num == 5 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &HeaderAuthRequest{}; if err := unmarshalHeaderAuthRequest(item, v); err != nil { return err }; m.Request = &AuthenticateRequest_HeaderAuth{HeaderAuth: item}; b = b[n:]")
	case kindSyncMapReqOneof:
		fmt.Fprintln(b, "\t\tcase num == 1 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &SyncMappingsInit{}; if err := unmarshalSyncMappingsInit(item, v); err != nil { return err }; m.Msg = &SyncMappingsRequest_Init{Init: item}; b = b[n:]")
		fmt.Fprintln(b, "\t\tcase num == 2 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; item := &SyncMappingsAck{}; if err := unmarshalSyncMappingsAck(item, v); err != nil { return err }; m.Msg = &SyncMappingsRequest_Ack{Ack: item}; b = b[n:]")
	case kindOptionalString:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeString(b); if n < 0 { return protowire.ParseError(n) }; m.%s = &v; b = b[n:]\n", f.Number, f.Name)
	case kindOptionalBytes:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s[:0], v...); if m.%s == nil { m.%s = []byte{} }; b = b[n:]\n", f.Number, f.Name, f.Name, f.Name, f.Name)
	case kindOptionalBool:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; x := protowire.DecodeBool(v); m.%s = &x; b = b[n:]\n", f.Number, f.Name)
	}
}

func emitMerge(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func merge%s(dst, src *%s) {\n", m.Name, m.Name)
	for _, f := range m.Fields {
		switch f.Kind {
		case kindString:
			fmt.Fprintf(b, "\tif src.%s != \"\" { dst.%s = src.%s }\n", f.Name, f.Name, f.Name)
		case kindBool:
			fmt.Fprintf(b, "\tif src.%s { dst.%s = src.%s }\n", f.Name, f.Name, f.Name)
		case kindInt32, kindInt64, kindUint32, kindUint64, kindEnum:
			fmt.Fprintf(b, "\tif src.%s != 0 { dst.%s = src.%s }\n", f.Name, f.Name, f.Name)
		case kindBytes:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { dst.%s = append(dst.%s[:0], src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif src.%s != nil { if dst.%s == nil { dst.%s = &%s{} }; merge%s(dst.%s, src.%s) }\n", f.Name, f.Name, f.Name, f.MessageType, f.MessageType, f.Name, f.Name)
		case kindTimestamp:
			fmt.Fprintf(b, "\tif src.%s != nil { if dst.%s == nil { dst.%s = &timestamppb.Timestamp{} }; mergeTimestamp(dst.%s, src.%s) }\n", f.Name, f.Name, f.Name, f.Name, f.Name)
		case kindDuration:
			fmt.Fprintf(b, "\tif src.%s != nil { if dst.%s == nil { dst.%s = &durationpb.Duration{} }; mergeDuration(dst.%s, src.%s) }\n", f.Name, f.Name, f.Name, f.Name, f.Name)
		case kindRepeatedUint32, kindRepeatedEnum:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { dst.%s = append(dst.%s, src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		case kindRepeatedString:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { dst.%s = append(dst.%s, src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		case kindRepeatedBytes:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { for _, v := range src.%s { dst.%s = append(dst.%s, append([]byte(nil), v...)) } }\n", f.Name, f.Name, f.Name, f.Name)
		case kindRepeatedMsg:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { for _, v := range src.%s { if v != nil { cp := &%s{}; merge%s(cp, v); dst.%s = append(dst.%s, cp) } } }\n", f.Name, f.Name, f.MessageType, f.MessageType, f.Name, f.Name)
		case kindMapStringMsg:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { if dst.%s == nil { dst.%s = make(map[string]*%s) }; for k, v := range src.%s { if v != nil { cp := &%s{}; merge%s(cp, v); dst.%s[k] = cp } else { dst.%s[k] = nil } } }\n", f.Name, f.Name, f.Name, f.MessageType, f.Name, f.MessageType, f.MessageType, f.Name, f.Name)
		case kindMapStringString:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { if dst.%s == nil { dst.%s = make(map[string]string) }; for k, v := range src.%s { dst.%s[k] = v } }\n", f.Name, f.Name, f.Name, f.Name, f.Name)
		case kindPortInfoOneof:
			fmt.Fprintln(b, "\tswitch v := src.PortSelection.(type) {")
			fmt.Fprintln(b, "\tcase *PortInfo_Port:")
			fmt.Fprintln(b, "\t\tdst.PortSelection = &PortInfo_Port{Port: v.Port}")
			fmt.Fprintln(b, "\tcase *PortInfo_Range_:")
			fmt.Fprintln(b, "\t\tif v.Range != nil { cp := &PortInfo_Range{}; mergePortInfo_Range(cp, v.Range); dst.PortSelection = &PortInfo_Range_{Range: cp} }")
			fmt.Fprintln(b, "\t}")
		case kindJobReqOneof:
			fmt.Fprintln(b, "\tswitch v := src.WorkloadParameters.(type) {")
			fmt.Fprintln(b, "\tcase *JobRequest_Bundle:")
			fmt.Fprintln(b, "\t\tif v.Bundle != nil { cp := &BundleParameters{}; mergeBundleParameters(cp, v.Bundle); dst.WorkloadParameters = &JobRequest_Bundle{Bundle: cp} }")
			fmt.Fprintln(b, "\t}")
		case kindJobRespOneof:
			fmt.Fprintln(b, "\tswitch v := src.WorkloadResults.(type) {")
			fmt.Fprintln(b, "\tcase *JobResponse_Bundle:")
			fmt.Fprintln(b, "\t\tif v.Bundle != nil { cp := &BundleResult{}; mergeBundleResult(cp, v.Bundle); dst.WorkloadResults = &JobResponse_Bundle{Bundle: cp} }")
			fmt.Fprintln(b, "\t}")
		case kindFlowFieldsOneof:
			fmt.Fprintln(b, "\tswitch v := src.ConnectionInfo.(type) {")
			fmt.Fprintln(b, "\tcase *FlowFields_PortInfo:")
			fmt.Fprintln(b, "\t\tif v.PortInfo != nil { cp := &PortInfo{}; mergePortInfo(cp, v.PortInfo); dst.ConnectionInfo = &FlowFields_PortInfo{PortInfo: cp} }")
			fmt.Fprintln(b, "\tcase *FlowFields_IcmpInfo:")
			fmt.Fprintln(b, "\t\tif v.IcmpInfo != nil { cp := &ICMPInfo{}; mergeICMPInfo(cp, v.IcmpInfo); dst.ConnectionInfo = &FlowFields_IcmpInfo{IcmpInfo: cp} }")
			fmt.Fprintln(b, "\t}")
		case kindAuthReqOneof:
			fmt.Fprintln(b, "\tswitch v := src.Request.(type) {")
			fmt.Fprintln(b, "\tcase *AuthenticateRequest_Password:")
			fmt.Fprintln(b, "\t\tif v.Password != nil { cp := &PasswordRequest{}; mergePasswordRequest(cp, v.Password); dst.Request = &AuthenticateRequest_Password{Password: cp} }")
			fmt.Fprintln(b, "\tcase *AuthenticateRequest_Pin:")
			fmt.Fprintln(b, "\t\tif v.Pin != nil { cp := &PinRequest{}; mergePinRequest(cp, v.Pin); dst.Request = &AuthenticateRequest_Pin{Pin: cp} }")
			fmt.Fprintln(b, "\tcase *AuthenticateRequest_HeaderAuth:")
			fmt.Fprintln(b, "\t\tif v.HeaderAuth != nil { cp := &HeaderAuthRequest{}; mergeHeaderAuthRequest(cp, v.HeaderAuth); dst.Request = &AuthenticateRequest_HeaderAuth{HeaderAuth: cp} }")
			fmt.Fprintln(b, "\t}")
		case kindSyncMapReqOneof:
			fmt.Fprintln(b, "\tswitch v := src.Msg.(type) {")
			fmt.Fprintln(b, "\tcase *SyncMappingsRequest_Init:")
			fmt.Fprintln(b, "\t\tif v.Init != nil { cp := &SyncMappingsInit{}; mergeSyncMappingsInit(cp, v.Init); dst.Msg = &SyncMappingsRequest_Init{Init: cp} }")
			fmt.Fprintln(b, "\tcase *SyncMappingsRequest_Ack:")
			fmt.Fprintln(b, "\t\tif v.Ack != nil { cp := &SyncMappingsAck{}; mergeSyncMappingsAck(cp, v.Ack); dst.Msg = &SyncMappingsRequest_Ack{Ack: cp} }")
			fmt.Fprintln(b, "\t}")
		case kindOptionalString, kindOptionalBool:
			fmt.Fprintf(b, "\tif src.%s != nil { v := *src.%s; dst.%s = &v }\n", f.Name, f.Name, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif src.%s != nil { dst.%s = append(dst.%s[:0], src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		}
	}
	fmt.Fprintln(b, "\tif len(src.unknownFields) > 0 { dst.unknownFields = append(dst.unknownFields, src.unknownFields...) }")
	fmt.Fprintln(b, "}\n")
}

func emitEqual(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func equal%s(a, b *%s) bool {\n", m.Name, m.Name)
	for _, f := range m.Fields {
		switch f.Kind {
		case kindString, kindBool, kindInt32, kindInt64, kindUint32, kindUint64, kindEnum:
			fmt.Fprintf(b, "\tif a.%s != b.%s { return false }\n", f.Name, f.Name)
		case kindBytes:
			fmt.Fprintf(b, "\tif !bytes.Equal(a.%s, b.%s) { return false }\n", f.Name, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif (a.%s == nil) != (b.%s == nil) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tif a.%s != nil && !equal%s(a.%s, b.%s) { return false }\n", f.Name, f.MessageType, f.Name, f.Name)
		case kindTimestamp:
			fmt.Fprintf(b, "\tif !equalTimestamp(a.%s, b.%s) { return false }\n", f.Name, f.Name)
		case kindDuration:
			fmt.Fprintf(b, "\tif !equalDuration(a.%s, b.%s) { return false }\n", f.Name, f.Name)
		case kindRepeatedUint32, kindRepeatedEnum:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor i := range a.%s { if a.%s[i] != b.%s[i] { return false } }\n", f.Name, f.Name, f.Name)
		case kindRepeatedString:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor i := range a.%s { if a.%s[i] != b.%s[i] { return false } }\n", f.Name, f.Name, f.Name)
		case kindRepeatedBytes:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor i := range a.%s { if !bytes.Equal(a.%s[i], b.%s[i]) { return false } }\n", f.Name, f.Name, f.Name)
		case kindRepeatedMsg:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor i := range a.%s { if (a.%s[i] == nil) != (b.%s[i] == nil) { return false }; if a.%s[i] != nil && !equal%s(a.%s[i], b.%s[i]) { return false } }\n", f.Name, f.Name, f.Name, f.Name, f.MessageType, f.Name, f.Name)
		case kindMapStringMsg:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor k, av := range a.%s { bv, ok := b.%s[k]; if !ok { return false }; if (av == nil) != (bv == nil) { return false }; if av != nil && !equal%s(av, bv) { return false } }\n", f.Name, f.Name, f.MessageType)
		case kindMapStringString:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor k, av := range a.%s { bv, ok := b.%s[k]; if !ok || av != bv { return false } }\n", f.Name, f.Name)
		case kindPortInfoOneof:
			fmt.Fprintln(b, "\tif !equalPortInfoSelection(a.PortSelection, b.PortSelection) { return false }")
		case kindJobReqOneof:
			fmt.Fprintln(b, "\tif !equalJobRequestWorkloadParameters(a.WorkloadParameters, b.WorkloadParameters) { return false }")
		case kindJobRespOneof:
			fmt.Fprintln(b, "\tif !equalJobResponseWorkloadResults(a.WorkloadResults, b.WorkloadResults) { return false }")
		case kindFlowFieldsOneof:
			fmt.Fprintln(b, "\tif !equalFlowFieldsConnectionInfo(a.ConnectionInfo, b.ConnectionInfo) { return false }")
		case kindAuthReqOneof:
			fmt.Fprintln(b, "\tif !equalAuthenticateRequestRequest(a.Request, b.Request) { return false }")
		case kindSyncMapReqOneof:
			fmt.Fprintln(b, "\tif !equalSyncMappingsRequestMsg(a.Msg, b.Msg) { return false }")
		case kindOptionalString, kindOptionalBool:
			fmt.Fprintf(b, "\tif (a.%s == nil) != (b.%s == nil) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tif a.%s != nil && *a.%s != *b.%s { return false }\n", f.Name, f.Name, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif (a.%s == nil) != (b.%s == nil) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tif !bytes.Equal(a.%s, b.%s) { return false }\n", f.Name, f.Name)
		}
	}
	fmt.Fprintln(b, "\tif !bytes.Equal(a.unknownFields, b.unknownFields) { return false }")
	fmt.Fprintln(b, "\treturn true\n}\n")
}

func lower(s string) string {
	return strings.ToLower(s[:1]) + s[1:]
}

func hasKind(t target, kind scalarKind) bool {
	for _, m := range t.Messages {
		for _, f := range m.Fields {
			if f.Kind == kind {
				return true
			}
		}
	}
	return false
}

func emitWellKnown(b *bytes.Buffer, name, typ string) {
	fmt.Fprintf(b, "func size%s(m *%s) int {\n", name, typ)
	fmt.Fprintln(b, "\tn := 0")
	fmt.Fprintln(b, "\tif m.Seconds != 0 { n += protowire.SizeTag(1) + protowire.SizeVarint(uint64(m.Seconds)) }")
	fmt.Fprintln(b, "\tif m.Nanos != 0 { n += protowire.SizeTag(2) + protowire.SizeVarint(uint64(m.Nanos)) }")
	fmt.Fprintln(b, "\treturn n")
	fmt.Fprintln(b, "}\n")

	fmt.Fprintf(b, "func marshal%s(b []byte, m *%s) []byte {\n", name, typ)
	fmt.Fprintln(b, "\tif m.Seconds != 0 { b = protowire.AppendTag(b, 1, protowire.VarintType); b = protowire.AppendVarint(b, uint64(m.Seconds)) }")
	fmt.Fprintln(b, "\tif m.Nanos != 0 { b = protowire.AppendTag(b, 2, protowire.VarintType); b = protowire.AppendVarint(b, uint64(m.Nanos)) }")
	fmt.Fprintln(b, "\treturn b")
	fmt.Fprintln(b, "}\n")

	fmt.Fprintf(b, "func unmarshal%s(m *%s, b []byte) error {\n", name, typ)
	fmt.Fprintln(b, "\t*m = "+typ+"{}")
	fmt.Fprintln(b, "\tfor len(b) > 0 {")
	fmt.Fprintln(b, "\t\tnum, typ, n := protowire.ConsumeTag(b)")
	fmt.Fprintln(b, "\t\tif n < 0 { return protowire.ParseError(n) }")
	fmt.Fprintln(b, "\t\tb = b[n:]")
	fmt.Fprintln(b, "\t\tswitch {")
	fmt.Fprintln(b, "\t\tcase num == 1 && typ == protowire.VarintType:")
	fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.Seconds = int64(v); b = b[n:]")
	fmt.Fprintln(b, "\t\tcase num == 2 && typ == protowire.VarintType:")
	fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.Nanos = int32(v); b = b[n:]")
	fmt.Fprintln(b, "\t\tdefault:")
	fmt.Fprintln(b, "\t\t\tskip := protowire.ConsumeFieldValue(num, typ, b); if skip < 0 { return protowire.ParseError(skip) }; b = b[skip:]")
	fmt.Fprintln(b, "\t\t}")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "\treturn nil")
	fmt.Fprintln(b, "}\n")

	fmt.Fprintf(b, "func merge%s(dst, src *%s) {\n", name, typ)
	fmt.Fprintln(b, "\tif src.Seconds != 0 { dst.Seconds = src.Seconds }")
	fmt.Fprintln(b, "\tif src.Nanos != 0 { dst.Nanos = src.Nanos }")
	fmt.Fprintln(b, "}\n")

	fmt.Fprintf(b, "func equal%s(a, b *%s) bool {\n", name, typ)
	fmt.Fprintln(b, "\tif (a == nil) != (b == nil) { return false }")
	fmt.Fprintln(b, "\tif a == nil { return true }")
	fmt.Fprintln(b, "\treturn a.Seconds == b.Seconds && a.Nanos == b.Nanos")
	fmt.Fprintln(b, "}\n")
}

func emitMapHelpers(b *bytes.Buffer, t target) {
	seen := make(map[string]bool)
	needsStringString := false
	for _, m := range t.Messages {
		for _, f := range m.Fields {
			if f.Kind == kindMapStringString {
				needsStringString = true
			}
			if f.Kind != kindMapStringMsg || seen[f.MessageType] {
				continue
			}
			seen[f.MessageType] = true
			fmt.Fprintf(b, "func consumeString%sEntry(b []byte) (string, *%s, error) {\n", f.MessageType, f.MessageType)
			fmt.Fprintf(b, "\tvar key string\n\tval := &%s{}\n", f.MessageType)
			fmt.Fprintln(b, "\tfor len(b) > 0 {")
			fmt.Fprintln(b, "\t\tnum, typ, n := protowire.ConsumeTag(b)")
			fmt.Fprintln(b, "\t\tif n < 0 { return \"\", nil, protowire.ParseError(n) }")
			fmt.Fprintln(b, "\t\tb = b[n:]")
			fmt.Fprintln(b, "\t\tswitch {")
			fmt.Fprintln(b, "\t\tcase num == 1 && typ == protowire.BytesType:")
			fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeString(b); if n < 0 { return \"\", nil, protowire.ParseError(n) }; key = v; b = b[n:]")
			fmt.Fprintln(b, "\t\tcase num == 2 && typ == protowire.BytesType:")
			fmt.Fprintf(b, "\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return \"\", nil, protowire.ParseError(n) }; if err := unmarshal%s(val, v); err != nil { return \"\", nil, err }; b = b[n:]\n", f.MessageType)
			fmt.Fprintln(b, "\t\tdefault:")
			fmt.Fprintln(b, "\t\t\tskip := protowire.ConsumeFieldValue(num, typ, b); if skip < 0 { return \"\", nil, protowire.ParseError(skip) }; b = b[skip:]")
			fmt.Fprintln(b, "\t\t}")
			fmt.Fprintln(b, "\t}")
			fmt.Fprintln(b, "\treturn key, val, nil")
			fmt.Fprintln(b, "}\n")
		}
	}
	if needsStringString {
		fmt.Fprintln(b, "func consumeStringStringEntry(b []byte) (string, string, error) {")
		fmt.Fprintln(b, "\tvar key string")
		fmt.Fprintln(b, "\tvar val string")
		fmt.Fprintln(b, "\tfor len(b) > 0 {")
		fmt.Fprintln(b, "\t\tnum, typ, n := protowire.ConsumeTag(b)")
		fmt.Fprintln(b, "\t\tif n < 0 { return \"\", \"\", protowire.ParseError(n) }")
		fmt.Fprintln(b, "\t\tb = b[n:]")
		fmt.Fprintln(b, "\t\tswitch {")
		fmt.Fprintln(b, "\t\tcase num == 1 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeString(b); if n < 0 { return \"\", \"\", protowire.ParseError(n) }; key = v; b = b[n:]")
		fmt.Fprintln(b, "\t\tcase num == 2 && typ == protowire.BytesType:")
		fmt.Fprintln(b, "\t\t\tv, n := protowire.ConsumeString(b); if n < 0 { return \"\", \"\", protowire.ParseError(n) }; val = v; b = b[n:]")
		fmt.Fprintln(b, "\t\tdefault:")
		fmt.Fprintln(b, "\t\t\tskip := protowire.ConsumeFieldValue(num, typ, b); if skip < 0 { return \"\", \"\", protowire.ParseError(skip) }; b = b[skip:]")
		fmt.Fprintln(b, "\t\t}")
		fmt.Fprintln(b, "\t}")
		fmt.Fprintln(b, "\treturn key, val, nil")
		fmt.Fprintln(b, "}\n")
	}
}

func emitPortInfoSelectionHelpers(b *bytes.Buffer) {
	fmt.Fprintln(b, "func equalPortInfoSelection(a, b isPortInfo_PortSelection) bool {")
	fmt.Fprintln(b, "\tswitch av := a.(type) {")
	fmt.Fprintln(b, "\tcase nil:")
	fmt.Fprintln(b, "\t\treturn b == nil")
	fmt.Fprintln(b, "\tcase *PortInfo_Port:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*PortInfo_Port); return ok && av.Port == bv.Port")
	fmt.Fprintln(b, "\tcase *PortInfo_Range_:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*PortInfo_Range_); return ok && equalPortInfo_Range(av.Range, bv.Range)")
	fmt.Fprintln(b, "\tdefault:")
	fmt.Fprintln(b, "\t\treturn false")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "}\n")
}

func emitJobRequestWorkloadHelpers(b *bytes.Buffer) {
	fmt.Fprintln(b, "func equalJobRequestWorkloadParameters(a, b isJobRequest_WorkloadParameters) bool {")
	fmt.Fprintln(b, "\tswitch av := a.(type) {")
	fmt.Fprintln(b, "\tcase nil:")
	fmt.Fprintln(b, "\t\treturn b == nil")
	fmt.Fprintln(b, "\tcase *JobRequest_Bundle:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*JobRequest_Bundle); return ok && equalBundleParameters(av.Bundle, bv.Bundle)")
	fmt.Fprintln(b, "\tdefault:")
	fmt.Fprintln(b, "\t\treturn false")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "}\n")
}

func emitJobResponseWorkloadHelpers(b *bytes.Buffer) {
	fmt.Fprintln(b, "func equalJobResponseWorkloadResults(a, b isJobResponse_WorkloadResults) bool {")
	fmt.Fprintln(b, "\tswitch av := a.(type) {")
	fmt.Fprintln(b, "\tcase nil:")
	fmt.Fprintln(b, "\t\treturn b == nil")
	fmt.Fprintln(b, "\tcase *JobResponse_Bundle:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*JobResponse_Bundle); return ok && equalBundleResult(av.Bundle, bv.Bundle)")
	fmt.Fprintln(b, "\tdefault:")
	fmt.Fprintln(b, "\t\treturn false")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "}\n")
}

func emitFlowFieldsConnectionInfoHelpers(b *bytes.Buffer) {
	fmt.Fprintln(b, "func equalFlowFieldsConnectionInfo(a, b isFlowFields_ConnectionInfo) bool {")
	fmt.Fprintln(b, "\tswitch av := a.(type) {")
	fmt.Fprintln(b, "\tcase nil:")
	fmt.Fprintln(b, "\t\treturn b == nil")
	fmt.Fprintln(b, "\tcase *FlowFields_PortInfo:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*FlowFields_PortInfo); return ok && equalPortInfo(av.PortInfo, bv.PortInfo)")
	fmt.Fprintln(b, "\tcase *FlowFields_IcmpInfo:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*FlowFields_IcmpInfo); return ok && equalICMPInfo(av.IcmpInfo, bv.IcmpInfo)")
	fmt.Fprintln(b, "\tdefault:")
	fmt.Fprintln(b, "\t\treturn false")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "}\n")
}

func emitAuthenticateRequestHelpers(b *bytes.Buffer) {
	fmt.Fprintln(b, "func equalAuthenticateRequestRequest(a, b isAuthenticateRequest_Request) bool {")
	fmt.Fprintln(b, "\tswitch av := a.(type) {")
	fmt.Fprintln(b, "\tcase nil:")
	fmt.Fprintln(b, "\t\treturn b == nil")
	fmt.Fprintln(b, "\tcase *AuthenticateRequest_Password:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*AuthenticateRequest_Password); return ok && equalPasswordRequest(av.Password, bv.Password)")
	fmt.Fprintln(b, "\tcase *AuthenticateRequest_Pin:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*AuthenticateRequest_Pin); return ok && equalPinRequest(av.Pin, bv.Pin)")
	fmt.Fprintln(b, "\tcase *AuthenticateRequest_HeaderAuth:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*AuthenticateRequest_HeaderAuth); return ok && equalHeaderAuthRequest(av.HeaderAuth, bv.HeaderAuth)")
	fmt.Fprintln(b, "\tdefault:")
	fmt.Fprintln(b, "\t\treturn false")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "}\n")
}

func emitSyncMappingsRequestHelpers(b *bytes.Buffer) {
	fmt.Fprintln(b, "func equalSyncMappingsRequestMsg(a, b isSyncMappingsRequest_Msg) bool {")
	fmt.Fprintln(b, "\tswitch av := a.(type) {")
	fmt.Fprintln(b, "\tcase nil:")
	fmt.Fprintln(b, "\t\treturn b == nil")
	fmt.Fprintln(b, "\tcase *SyncMappingsRequest_Init:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*SyncMappingsRequest_Init); return ok && equalSyncMappingsInit(av.Init, bv.Init)")
	fmt.Fprintln(b, "\tcase *SyncMappingsRequest_Ack:")
	fmt.Fprintln(b, "\t\tbv, ok := b.(*SyncMappingsRequest_Ack); return ok && equalSyncMappingsAck(av.Ack, bv.Ack)")
	fmt.Fprintln(b, "\tdefault:")
	fmt.Fprintln(b, "\t\treturn false")
	fmt.Fprintln(b, "\t}")
	fmt.Fprintln(b, "}\n")
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
