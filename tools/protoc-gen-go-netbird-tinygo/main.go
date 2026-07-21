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
	kindString         scalarKind = "string"
	kindBytes          scalarKind = "bytes"
	kindInt32          scalarKind = "int32"
	kindUint32         scalarKind = "uint32"
	kindEnum           scalarKind = "enum"
	kindMessage        scalarKind = "message"
	kindRepeatedUint32 scalarKind = "repeated_uint32"
	kindOptionalString scalarKind = "optional_string"
	kindOptionalBytes  scalarKind = "optional_bytes"
	kindOptionalBool   scalarKind = "optional_bool"
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
	Name       string
	Package    string
	Canary     string
	Prefix     string
	OutputDir  string
	PBFile     string
	Messages   []message
	TestSource string
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
		},
	},
}

func main() {
	var targetName string
	var repoRoot string
	flag.StringVar(&targetName, "target", "", "target proto package to generate: signal or management")
	flag.StringVar(&repoRoot, "repo-root", ".", "repository root")
	flag.Parse()

	t, ok := targets[targetName]
	if !ok {
		failf("unknown -target %q", targetName)
	}

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
	fmt.Fprintln(&b, ")\n")

	for _, m := range t.Messages {
		fmt.Fprintf(&b, "type %sReflect struct{ m *%s }\n", lower(m.Name), m.Name)
	}
	fmt.Fprintf(&b, "\nfunc protoCanary(method string) string { return %q + method }\n\n", t.Canary+": unexpected protoreflect.Message.")
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
	fmt.Fprintf(b, "func (r %s) GetUnknown() protoreflect.RawFields { return nil }\n", w)
	fmt.Fprintf(b, "func (r %s) SetUnknown(protoreflect.RawFields) {}\n", w)
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
		case kindInt32, kindUint32, kindEnum:
			fmt.Fprintf(b, "\tif m.%s != 0 { n += protowire.SizeTag(%d) + protowire.SizeVarint(uint64(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif m.%s != nil { s := size%s(m.%s); n += protowire.SizeTag(%d) + protowire.SizeBytes(s) }\n", f.Name, f.MessageType, f.Name, f.Number)
		case kindRepeatedUint32:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { packed := 0; for _, v := range m.%s { packed += protowire.SizeVarint(uint64(v)) }; n += protowire.SizeTag(%d) + protowire.SizeBytes(packed) }\n", f.Name, f.Name, f.Number)
		case kindOptionalString:
			fmt.Fprintf(b, "\tif m.%s != nil { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(*m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif m.%s != nil { n += protowire.SizeTag(%d) + protowire.SizeBytes(len(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBool:
			fmt.Fprintf(b, "\tif m.%s != nil { n += protowire.SizeTag(%d) + protowire.SizeVarint(protowire.EncodeBool(*m.%s)) }\n", f.Name, f.Number, f.Name)
		}
	}
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
		case kindInt32, kindUint32, kindEnum:
			fmt.Fprintf(b, "\tif m.%s != 0 { b = protowire.AppendTag(b, %d, protowire.VarintType); b = protowire.AppendVarint(b, uint64(m.%s)) }\n", f.Name, f.Number, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(size%s(m.%s))); b = marshal%s(b, m.%s) }\n", f.Name, f.Number, f.MessageType, f.Name, f.MessageType, f.Name)
		case kindRepeatedUint32:
			fmt.Fprintf(b, "\tif len(m.%s) > 0 { packed := 0; for _, v := range m.%s { packed += protowire.SizeVarint(uint64(v)) }; b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendVarint(b, uint64(packed)); for _, v := range m.%s { b = protowire.AppendVarint(b, uint64(v)) } }\n", f.Name, f.Name, f.Number, f.Name)
		case kindOptionalString:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendString(b, *m.%s) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.BytesType); b = protowire.AppendBytes(b, m.%s) }\n", f.Name, f.Number, f.Name)
		case kindOptionalBool:
			fmt.Fprintf(b, "\tif m.%s != nil { b = protowire.AppendTag(b, %d, protowire.VarintType); b = protowire.AppendVarint(b, protowire.EncodeBool(*m.%s)) }\n", f.Name, f.Number, f.Name)
		}
	}
	fmt.Fprintln(b, "\treturn b\n}\n")
}

func emitUnmarshal(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func unmarshal%s(m *%s, b []byte) error {\n\t*m = %s{}\n\tfor len(b) > 0 {\n\t\tnum, typ, n := protowire.ConsumeTag(b)\n\t\tif n < 0 { return protowire.ParseError(n) }\n\t\tb = b[n:]\n\t\tswitch {\n", m.Name, m.Name, m.Name)
	for _, f := range m.Fields {
		emitUnmarshalCase(b, f)
	}
	fmt.Fprintln(b, "\t\tdefault:")
	fmt.Fprintln(b, "\t\t\tskip := protowire.ConsumeFieldValue(num, typ, b)")
	fmt.Fprintln(b, "\t\t\tif skip < 0 { return protowire.ParseError(skip) }")
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
	case kindInt32:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = int32(v); b = b[n:]\n", f.Number, f.Name)
	case kindUint32:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = uint32(v); b = b[n:]\n", f.Number, f.Name)
	case kindEnum:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = %s(v); b = b[n:]\n", f.Number, f.Name, f.EnumType)
	case kindMessage:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; if m.%s == nil { m.%s = &%s{} }; if err := unmarshal%s(m.%s, v); err != nil { return err }; b = b[n:]\n", f.Number, f.Name, f.Name, f.MessageType, f.MessageType, f.Name)
	case kindRepeatedUint32:
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.BytesType:\n\t\t\tv, n := protowire.ConsumeBytes(b); if n < 0 { return protowire.ParseError(n) }; for len(v) > 0 { item, consumed := protowire.ConsumeVarint(v); if consumed < 0 { return protowire.ParseError(consumed) }; m.%s = append(m.%s, uint32(item)); v = v[consumed:] }; b = b[n:]\n", f.Number, f.Name, f.Name)
		fmt.Fprintf(b, "\t\tcase num == %d && typ == protowire.VarintType:\n\t\t\tv, n := protowire.ConsumeVarint(b); if n < 0 { return protowire.ParseError(n) }; m.%s = append(m.%s, uint32(v)); b = b[n:]\n", f.Number, f.Name, f.Name)
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
		case kindInt32, kindUint32, kindEnum:
			fmt.Fprintf(b, "\tif src.%s != 0 { dst.%s = src.%s }\n", f.Name, f.Name, f.Name)
		case kindBytes:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { dst.%s = append(dst.%s[:0], src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif src.%s != nil { if dst.%s == nil { dst.%s = &%s{} }; merge%s(dst.%s, src.%s) }\n", f.Name, f.Name, f.Name, f.MessageType, f.MessageType, f.Name, f.Name)
		case kindRepeatedUint32:
			fmt.Fprintf(b, "\tif len(src.%s) > 0 { dst.%s = append(dst.%s, src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		case kindOptionalString, kindOptionalBool:
			fmt.Fprintf(b, "\tif src.%s != nil { v := *src.%s; dst.%s = &v }\n", f.Name, f.Name, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif src.%s != nil { dst.%s = append(dst.%s[:0], src.%s...) }\n", f.Name, f.Name, f.Name, f.Name)
		}
	}
	fmt.Fprintln(b, "}\n")
}

func emitEqual(b *bytes.Buffer, m message) {
	fmt.Fprintf(b, "func equal%s(a, b *%s) bool {\n", m.Name, m.Name)
	for _, f := range m.Fields {
		switch f.Kind {
		case kindString, kindInt32, kindUint32, kindEnum:
			fmt.Fprintf(b, "\tif a.%s != b.%s { return false }\n", f.Name, f.Name)
		case kindBytes:
			fmt.Fprintf(b, "\tif !bytes.Equal(a.%s, b.%s) { return false }\n", f.Name, f.Name)
		case kindMessage:
			fmt.Fprintf(b, "\tif (a.%s == nil) != (b.%s == nil) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tif a.%s != nil && !equal%s(a.%s, b.%s) { return false }\n", f.Name, f.MessageType, f.Name, f.Name)
		case kindRepeatedUint32:
			fmt.Fprintf(b, "\tif len(a.%s) != len(b.%s) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tfor i := range a.%s { if a.%s[i] != b.%s[i] { return false } }\n", f.Name, f.Name, f.Name)
		case kindOptionalString, kindOptionalBool:
			fmt.Fprintf(b, "\tif (a.%s == nil) != (b.%s == nil) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tif a.%s != nil && *a.%s != *b.%s { return false }\n", f.Name, f.Name, f.Name)
		case kindOptionalBytes:
			fmt.Fprintf(b, "\tif (a.%s == nil) != (b.%s == nil) { return false }\n", f.Name, f.Name)
			fmt.Fprintf(b, "\tif !bytes.Equal(a.%s, b.%s) { return false }\n", f.Name, f.Name)
		}
	}
	fmt.Fprintln(b, "\treturn true\n}\n")
}

func lower(s string) string {
	return strings.ToLower(s[:1]) + s[1:]
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
