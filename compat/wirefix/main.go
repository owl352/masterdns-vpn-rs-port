// Wire-compatibility fixtures between the Go MasterDnsVPN code and this Rust port.
//
// This file is compiled INTO the Go module (it imports its internal packages)
// with `go build -overlay`, so nothing is written into the Go repository; see
// compat/wirefix.sh.
//
//	wirefix gen <out.json>     bytes produced by Go code, for the Rust tests to check
//	wirefix check <in.json>    bytes produced by Rust code, parsed with the Go
//	                           client's own code; exits 1 on any mismatch
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sort"

	basecodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/compression"
	dnsparser "masterdnsvpn-go/internal/dnsparser"
	enums "masterdnsvpn-go/internal/enums"
	security "masterdnsvpn-go/internal/security"
	vpnproto "masterdnsvpn-go/internal/vpnproto"
)

type Frame struct {
	PacketType      uint8  `json:"packet_type"`
	SessionID       uint8  `json:"session_id"`
	SessionCookie   uint8  `json:"session_cookie"`
	StreamID        uint16 `json:"stream_id"`
	SequenceNum     uint16 `json:"sequence_num"`
	FragmentID      uint8  `json:"fragment_id"`
	TotalFragments  uint8  `json:"total_fragments"`
	CompressionType uint8  `json:"compression_type"`
	Payload         string `json:"payload"`
}

type FrameCase struct {
	Frame
	Raw string `json:"raw"`
}

type PackedCase struct {
	Blocks [][5]int `json:"blocks"`
	Raw    string   `json:"raw"`
}

type Policy struct {
	MaxPacketDuplicationCount int     `json:"max_packet_duplication_count"`
	MaxSetupDuplicationCount  int     `json:"max_setup_duplication_count"`
	MaxUploadMTU              int     `json:"max_upload_mtu"`
	MaxDownloadMTU            int     `json:"max_download_mtu"`
	MaxRxTxWorkers            int     `json:"max_rx_tx_workers"`
	MinPingAggressiveInterval float64 `json:"min_ping_aggressive_interval"`
	MaxPacketsPerBatch        int     `json:"max_packets_per_batch"`
	MaxARQWindowSize          int     `json:"max_arq_window_size"`
	MaxARQDataNackMaxGap      int     `json:"max_arq_data_nack_max_gap"`
	MinCompressionMinSize     int     `json:"min_compression_min_size"`
	MinARQInitialRTOSeconds   float64 `json:"min_arq_initial_rto_seconds"`
}

type SessionAcceptCase struct {
	SessionID       uint8  `json:"session_id"`
	SessionCookie   uint8  `json:"session_cookie"`
	CompressionPair uint8  `json:"compression_pair"`
	VerifyCode      string `json:"verify_code"`
	HasPolicy       bool   `json:"has_policy"`
	Policy          Policy `json:"policy"`
	Raw             string `json:"raw"`
}

type EncodingCase struct {
	Data    string `json:"data"`
	Encoded string `json:"encoded"`
}

type CodecCase struct {
	Method  int    `json:"method"`
	Key     string `json:"key"`
	Plain   string `json:"plain"`
	Encoded string `json:"encoded"`
}

type CompressionCase struct {
	Type       uint8  `json:"type"`
	Data       string `json:"data"`
	Compressed string `json:"compressed"`
}

type QueryCase struct {
	Domain  string `json:"domain"`
	Method  int    `json:"method"`
	Key     string `json:"key"`
	Frame   Frame  `json:"frame"`
	Encoded string `json:"encoded"`
	Packet  string `json:"packet"`
}

type ResponseCase struct {
	BaseEncode bool   `json:"base_encode"`
	Question   string `json:"question"`
	AnswerName string `json:"answer_name"`
	Frame      Frame  `json:"frame"`
	Response   string `json:"response"`
}

type Fixtures struct {
	Producer           string              `json:"producer"`
	Frames             []FrameCase         `json:"frames"`
	InvalidPacketTypes []int               `json:"invalid_packet_types,omitempty"`
	Packed             []PackedCase        `json:"packed"`
	SessionAccept      []SessionAcceptCase `json:"session_accept"`
	Base36             []EncodingCase      `json:"base36"`
	Base64             []EncodingCase      `json:"base64"`
	Codec              []CodecCase         `json:"codec"`
	Compression        []CompressionCase   `json:"compression"`
	Queries            []QueryCase         `json:"queries,omitempty"`
	Responses          []ResponseCase      `json:"responses"`
}

const codecKey = "compat-fixture-key"

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func (f Frame) buildOptions() vpnproto.BuildOptions {
	return vpnproto.BuildOptions{
		SessionID:       f.SessionID,
		PacketType:      f.PacketType,
		SessionCookie:   f.SessionCookie,
		StreamID:        f.StreamID,
		SequenceNum:     f.SequenceNum,
		FragmentID:      f.FragmentID,
		TotalFragments:  f.TotalFragments,
		CompressionType: f.CompressionType,
		Payload:         unhex(f.Payload),
	}
}

func frameFromPacket(p vpnproto.Packet) Frame {
	f := Frame{PacketType: p.PacketType, SessionID: p.SessionID, SessionCookie: p.SessionCookie, Payload: hx(p.Payload)}
	if p.HasStreamID {
		f.StreamID = p.StreamID
	}
	if p.HasSequenceNum {
		f.SequenceNum = p.SequenceNum
	}
	if p.HasFragmentInfo {
		f.FragmentID, f.TotalFragments = p.FragmentID, p.TotalFragments
	}
	if p.HasCompressionType {
		f.CompressionType = p.CompressionType
	}
	return f
}

// expectedAfterParse zeroes the fields a packet type does not carry on the wire.
func expectedAfterParse(f Frame) Frame {
	t := f.PacketType
	raw, err := vpnproto.BuildRaw(vpnproto.BuildOptions{PacketType: t})
	if err != nil {
		return f
	}
	p, err := vpnproto.Parse(raw)
	if err != nil {
		return f
	}
	if !p.HasStreamID {
		f.StreamID = 0
	}
	if !p.HasSequenceNum {
		f.SequenceNum = 0
	}
	if !p.HasFragmentInfo {
		f.FragmentID, f.TotalFragments = 0, 0
	}
	if !p.HasCompressionType {
		f.CompressionType = 0
	}
	return f
}

func sampleBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}

func compressibleBytes(n int) []byte {
	return bytes.Repeat([]byte("masterdnsvpn compat payload "), n/28+1)[:n]
}

func toVpnPolicy(p Policy) vpnproto.SessionAcceptClientPolicy {
	return vpnproto.SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: p.MaxPacketDuplicationCount,
		MaxSetupDuplicationCount:  p.MaxSetupDuplicationCount,
		MaxUploadMTU:              p.MaxUploadMTU,
		MaxDownloadMTU:            p.MaxDownloadMTU,
		MaxRxTxWorkers:            p.MaxRxTxWorkers,
		MinPingAggressiveInterval: p.MinPingAggressiveInterval,
		MaxPacketsPerBatch:        p.MaxPacketsPerBatch,
		MaxARQWindowSize:          p.MaxARQWindowSize,
		MaxARQDataNackMaxGap:      p.MaxARQDataNackMaxGap,
		MinCompressionMinSize:     p.MinCompressionMinSize,
		MinARQInitialRTOSeconds:   p.MinARQInitialRTOSeconds,
	}
}

func generate() Fixtures {
	r := rand.New(rand.NewSource(20260928))
	fx := Fixtures{Producer: "go"}

	// Every packet type: valid ones become frames, the rest must be rejected.
	for t := 0; t < 256; t++ {
		f := Frame{PacketType: uint8(t), SessionID: 7, SessionCookie: 0x5A, StreamID: 0x1234, SequenceNum: 0xBEEF, FragmentID: 2, TotalFragments: 5, Payload: hx([]byte("hello-compat"))}
		raw, err := vpnproto.BuildRaw(f.buildOptions())
		if err != nil {
			fx.InvalidPacketTypes = append(fx.InvalidPacketTypes, t)
			continue
		}
		fx.Frames = append(fx.Frames, FrameCase{Frame: expectedAfterParse(f), Raw: hx(raw)})
	}
	// Edge frames: empty payload, compression byte set, max field values.
	for _, f := range []Frame{
		{PacketType: enums.PACKET_PING, SessionID: 1, SessionCookie: 2, Payload: ""},
		{PacketType: enums.PACKET_STREAM_DATA, SessionID: 255, SessionCookie: 255, StreamID: 0xFFFF, SequenceNum: 0xFFFF, FragmentID: 255, TotalFragments: 255, CompressionType: 1, Payload: hx(sampleBytes(r, 300))},
		{PacketType: enums.PACKET_PACKED_CONTROL_BLOCKS, SessionID: 3, SessionCookie: 4, Payload: hx(sampleBytes(r, 14))},
	} {
		raw, err := vpnproto.BuildRaw(f.buildOptions())
		if err != nil {
			panic(err)
		}
		fx.Frames = append(fx.Frames, FrameCase{Frame: expectedAfterParse(f), Raw: hx(raw)})
	}

	// Packed control blocks.
	blocks := [][5]int{
		{enums.PACKET_STREAM_DATA_ACK, 1, 0, 0, 0},
		{enums.PACKET_STREAM_DATA_ACK, 1, 65535, 0, 0},
		{enums.PACKET_STREAM_DATA_NACK, 0x1234, 0xBEEF, 3, 9},
		{enums.PACKET_SOCKS5_CONNECTED_ACK, 65535, 1, 0, 0},
	}
	var packed []byte
	for _, b := range blocks {
		packed = vpnproto.AppendPackedControlBlock(packed, uint8(b[0]), uint16(b[1]), uint16(b[2]), uint8(b[3]), uint8(b[4]))
	}
	fx.Packed = append(fx.Packed, PackedCase{Blocks: blocks, Raw: hx(packed)})

	// SESSION_ACCEPT, with and without the client policy block.
	policy := Policy{
		MaxPacketDuplicationCount: 5, MaxSetupDuplicationCount: 6, MaxUploadMTU: 150, MaxDownloadMTU: 4096,
		MaxRxTxWorkers: 255, MinPingAggressiveInterval: 0.05, MaxPacketsPerBatch: 20, MaxARQWindowSize: 8000,
		MaxARQDataNackMaxGap: 255, MinCompressionMinSize: 120, MinARQInitialRTOSeconds: 0.35,
	}
	for _, withPolicy := range []bool{false, true} {
		sa := vpnproto.SessionAcceptPayload{SessionID: 9, SessionCookie: 0xA7, CompressionPair: 0x13, VerifyCode: [4]byte{1, 2, 3, 4}, HasClientPolicySync: withPolicy}
		if withPolicy {
			sa.ClientPolicy = toVpnPolicy(policy)
		}
		c := SessionAcceptCase{SessionID: 9, SessionCookie: 0xA7, CompressionPair: 0x13, VerifyCode: hx(sa.VerifyCode[:]), HasPolicy: withPolicy, Raw: hx(vpnproto.EncodeSessionAcceptPayload(sa))}
		if withPolicy {
			c.Policy = policy
		}
		fx.SessionAccept = append(fx.SessionAccept, c)
	}

	// Label and TXT encodings.
	inputs := [][]byte{{}, {0}, {0, 0, 1}, {0xFF}, []byte("abc")}
	for _, n := range []int{7, 32, 63, 100, 150} {
		inputs = append(inputs, sampleBytes(r, n))
	}
	for _, in := range inputs {
		fx.Base36 = append(fx.Base36, EncodingCase{Data: hx(in), Encoded: basecodec.EncodeLowerBase36(in)})
		fx.Base64 = append(fx.Base64, EncodingCase{Data: hx(in), Encoded: string(basecodec.EncodeRawBase64(in))})
	}

	// Every cipher method.
	for method := 0; method <= 5; method++ {
		codec, err := security.NewCodec(method, codecKey)
		if err != nil {
			panic(err)
		}
		for _, plain := range [][]byte{[]byte("x"), sampleBytes(r, 140)} {
			enc, err := codec.EncryptAndEncode(plain)
			if err != nil {
				panic(err)
			}
			fx.Codec = append(fx.Codec, CodecCase{Method: method, Key: codecKey, Plain: hx(plain), Encoded: enc})
		}
	}

	// Compression (only decompression must match across implementations).
	for _, t := range []uint8{compression.TypeZSTD, compression.TypeLZ4, compression.TypeZLIB} {
		data := compressibleBytes(2000)
		comp, used := compression.CompressPayload(data, t, compression.DefaultMinSize)
		if used != t {
			panic(fmt.Sprintf("compression type %d not used", t))
		}
		fx.Compression = append(fx.Compression, CompressionCase{Type: t, Data: hx(data), Compressed: hx(comp)})
	}

	// Queries exactly as the Go client builds them.
	for _, method := range []int{0, 1, 2, 5} {
		codec, _ := security.NewCodec(method, codecKey)
		for _, f := range []Frame{
			{PacketType: enums.PACKET_PING, SessionID: 3, SessionCookie: 0x33, Payload: hx(sampleBytes(r, 7))},
			{PacketType: enums.PACKET_STREAM_DATA, SessionID: 3, SessionCookie: 0x33, StreamID: 5, SequenceNum: 777, Payload: hx(sampleBytes(r, 60))},
		} {
			enc, err := vpnproto.BuildEncodedAuto(f.buildOptions(), codec, compression.DefaultMinSize)
			if err != nil {
				panic(err)
			}
			q, err := dnsparser.BuildTunnelTXTQuestionPacket("v.example.com", []byte(enc), enums.DNS_RECORD_TYPE_TXT, 1232)
			if err != nil {
				panic(err)
			}
			fx.Queries = append(fx.Queries, QueryCase{Domain: "v.example.com", Method: method, Key: codecKey, Frame: expectedAfterParse(f), Encoded: enc, Packet: hx(q)})
		}
	}

	// Responses exactly as the Go server builds them (legacy multi-record layout for big frames).
	question, err := dnsparser.BuildTunnelTXTQuestionPacket("v.example.com", []byte("aaaa0123456789"), enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		panic(err)
	}
	qp, err := dnsparser.ParsePacket(question)
	if err != nil {
		panic(err)
	}
	fx.Responses = append(fx.Responses, responseCases(question, qp.Questions[0].Name, r, func(q []byte, name string, p vpnproto.Packet, b bool) ([]byte, error) {
		return dnsparser.BuildVPNResponsePacket(q, name, p, b)
	})...)
	return fx
}

func responseCases(question []byte, name string, r *rand.Rand, build func([]byte, string, vpnproto.Packet, bool) ([]byte, error)) []ResponseCase {
	var out []ResponseCase
	frames := []Frame{
		{PacketType: enums.PACKET_PONG, SessionID: 3, SessionCookie: 0x33, Payload: hx(sampleBytes(r, 7))},
		{PacketType: enums.PACKET_STREAM_DATA, SessionID: 3, SessionCookie: 0x33, StreamID: 5, SequenceNum: 42, Payload: hx(sampleBytes(r, 180))},
		{PacketType: enums.PACKET_STREAM_DATA, SessionID: 3, SessionCookie: 0x33, StreamID: 5, SequenceNum: 43, Payload: hx(sampleBytes(r, 1500))},
		{PacketType: enums.PACKET_STREAM_DATA, SessionID: 3, SessionCookie: 0x33, StreamID: 5, SequenceNum: 44, CompressionType: compression.TypeZSTD, Payload: hx(compressibleBytes(3000))},
	}
	for _, base := range []bool{false, true} {
		for _, f := range frames {
			o := f.buildOptions()
			p := vpnproto.Packet{
				SessionID: o.SessionID, PacketType: o.PacketType, SessionCookie: o.SessionCookie,
				StreamID: o.StreamID, SequenceNum: o.SequenceNum, FragmentID: o.FragmentID, TotalFragments: o.TotalFragments,
				CompressionType: o.CompressionType, Payload: o.Payload,
			}
			resp, err := build(question, name, p, base)
			if err != nil {
				panic(err)
			}
			exp := expectedAfterParse(f)
			exp.CompressionType = 0 // the receiver sees the inflated payload
			out = append(out, ResponseCase{BaseEncode: base, Question: hx(question), AnswerName: name, Frame: exp, Response: hx(resp)})
		}
	}
	return out
}

// ---- check: parse Rust-produced bytes with the Go client's code ----

type checker struct{ failures []string }

func (c *checker) fail(format string, args ...any) {
	c.failures = append(c.failures, fmt.Sprintf(format, args...))
}

func (c *checker) sameFrame(ctx string, got vpnproto.Packet, want Frame, ignoreCompression bool) {
	g := frameFromPacket(got)
	if ignoreCompression {
		g.CompressionType = 0
		want.CompressionType = 0
	}
	if g != want {
		c.fail("%s: parsed %+v, want %+v", ctx, g, want)
	}
}

func check(fx Fixtures) *checker {
	c := &checker{}
	for i, fc := range fx.Frames {
		p, err := vpnproto.Parse(unhex(fc.Raw))
		if err != nil {
			c.fail("frame[%d] type 0x%02x: Go parse error: %v", i, fc.PacketType, err)
			continue
		}
		c.sameFrame(fmt.Sprintf("frame[%d] type 0x%02x", i, fc.PacketType), p, fc.Frame, false)
	}
	for i, pc := range fx.Packed {
		var got [][5]int
		vpnproto.ForEachPackedControlBlock(unhex(pc.Raw), func(t uint8, s uint16, sn uint16, fr uint8, tot uint8) bool {
			got = append(got, [5]int{int(t), int(s), int(sn), int(fr), int(tot)})
			return true
		})
		if fmt.Sprint(got) != fmt.Sprint(pc.Blocks) {
			c.fail("packed[%d]: Go read %v, want %v", i, got, pc.Blocks)
		}
	}
	for i, sc := range fx.SessionAccept {
		sa, err := vpnproto.DecodeSessionAcceptPayload(unhex(sc.Raw))
		if err != nil {
			c.fail("session_accept[%d]: %v", i, err)
			continue
		}
		if sa.SessionID != sc.SessionID || sa.SessionCookie != sc.SessionCookie || sa.CompressionPair != sc.CompressionPair || hx(sa.VerifyCode[:]) != sc.VerifyCode || sa.HasClientPolicySync != sc.HasPolicy {
			c.fail("session_accept[%d]: header fields differ: %+v", i, sa)
		}
		if sc.HasPolicy {
			// Scaled bytes are lossy; compare against Go's own encode/decode of the same policy.
			want, _ := vpnproto.DecodeSessionAcceptClientPolicy(func() []byte {
				b := vpnproto.EncodeSessionAcceptClientPolicy(toVpnPolicy(sc.Policy))
				return b[:]
			}())
			if sa.ClientPolicy != want {
				c.fail("session_accept[%d]: policy %+v, want %+v", i, sa.ClientPolicy, want)
			}
		}
	}
	for i, ec := range fx.Base36 {
		got, err := basecodec.DecodeLowerBase36String(ec.Encoded)
		if err != nil || hx(got) != ec.Data {
			c.fail("base36[%d]: decoded %x (err %v), want %s", i, got, err, ec.Data)
		}
		if enc := basecodec.EncodeLowerBase36(unhex(ec.Data)); enc != ec.Encoded {
			c.fail("base36[%d]: Go encodes %q, Rust %q", i, enc, ec.Encoded)
		}
	}
	for i, ec := range fx.Base64 {
		got, err := basecodec.DecodeRawBase64([]byte(ec.Encoded))
		if err != nil || hx(got) != ec.Data {
			c.fail("base64[%d]: decoded %x (err %v), want %s", i, got, err, ec.Data)
		}
	}
	for i, cc := range fx.Codec {
		codec, err := security.NewCodec(cc.Method, cc.Key)
		if err != nil {
			c.fail("codec[%d]: %v", i, err)
			continue
		}
		got, err := codec.DecodeStringAndDecrypt(cc.Encoded)
		if err != nil || hx(got) != cc.Plain {
			c.fail("codec[%d] method %d: Go decrypt %x (err %v), want %s", i, cc.Method, got, err, cc.Plain)
		}
	}
	for i, cc := range fx.Compression {
		got, ok := compression.TryDecompressPayload(unhex(cc.Compressed), cc.Type)
		if !ok || hx(got) != cc.Data {
			c.fail("compression[%d] type %d: Go could not decompress Rust output", i, cc.Type)
		}
	}
	for i, rc := range fx.Responses {
		p, err := dnsparser.ExtractVPNResponse(unhex(rc.Response), rc.BaseEncode)
		if err != nil {
			c.fail("response[%d] base=%v: Go client could not parse Rust response: %v", i, rc.BaseEncode, err)
			continue
		}
		c.sameFrame(fmt.Sprintf("response[%d] base=%v", i, rc.BaseEncode), p, rc.Frame, true)
	}
	return c
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: wirefix gen <out.json> | wirefix check <in.json>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		fx := generate()
		sort.Ints(fx.InvalidPacketTypes)
		data, _ := json.MarshalIndent(fx, "", " ")
		if err := os.WriteFile(os.Args[2], append(data, '\n'), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %s: %d frames, %d invalid types, %d session_accept, %d base36, %d codec, %d compression, %d queries, %d responses\n",
			os.Args[2], len(fx.Frames), len(fx.InvalidPacketTypes), len(fx.SessionAccept), len(fx.Base36), len(fx.Codec), len(fx.Compression), len(fx.Queries), len(fx.Responses))
	case "check":
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			panic(err)
		}
		var fx Fixtures
		if err := json.Unmarshal(data, &fx); err != nil {
			panic(err)
		}
		c := check(fx)
		total := len(fx.Frames) + len(fx.Packed) + len(fx.SessionAccept) + len(fx.Base36) + len(fx.Base64) + len(fx.Codec) + len(fx.Compression) + len(fx.Responses)
		if len(c.failures) > 0 {
			for _, f := range c.failures {
				fmt.Println("FAIL", f)
			}
			fmt.Printf("Go check of %s output: %d cases, %d FAILED\n", fx.Producer, total, len(c.failures))
			os.Exit(1)
		}
		fmt.Printf("Go check of %s output: %d cases, all passed\n", fx.Producer, total)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}
