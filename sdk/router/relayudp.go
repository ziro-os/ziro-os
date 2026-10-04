package router

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
)

// UDP relaying. A device's relay TLS connection hands it a session (FrameSession: ID + 32-byte
// key). The device then sends a hello over UDP, from its WireGuard socket, carrying a timestamp
// and an HMAC under the session key; the relay binds the session to the hello's source address
// and accepts relayed packets only from there. Relayed packets carry no MAC of their own:
// WireGuard authenticates them end to end, and the relay identifies the sender by session.
//
//	hello  0xE0 | session u32 | unix ms u64 | HMAC-SHA256(key, session|ms)   45 bytes
//	ack    0xE1 | session u32 | unix ms u64 | observed addr (16 + port 2)    31 bytes (< hello: no amplification)
//	send   0xE2 | session u32 | destination key [32] | packet
//	recv   0xE3 | source key [32] | packet
//
// The first byte never collides with STUN (0x00/0x01), WireGuard (1..4) or disco ("ZRD1").

const (
	FrameSession = 4 // relay -> device over TLS: session u32 + key [32]

	UDPHello = 0xE0
	UDPAck   = 0xE1
	UDPSend  = 0xE2
	UDPRecv  = 0xE3

	UDPHelloLen = 1 + 4 + 8 + 32
	UDPAckLen   = 1 + 4 + 8 + 18
	UDPSendHdr  = 1 + 4 + 32
	UDPRecvHdr  = 1 + 32
)

func helloMAC(key [32]byte, session uint32, ms uint64) []byte {
	m := hmac.New(sha256.New, key[:])
	var b [12]byte
	binary.BigEndian.PutUint32(b[:4], session)
	binary.BigEndian.PutUint64(b[4:], ms)
	m.Write([]byte("zr-relay-hello"))
	m.Write(b[:])
	return m.Sum(nil)
}

// UDPHelloPacket builds a hello for session at time ms (unix milliseconds).
func UDPHelloPacket(session uint32, key [32]byte, ms uint64) []byte {
	b := make([]byte, 13, UDPHelloLen)
	b[0] = UDPHello
	binary.BigEndian.PutUint32(b[1:], session)
	binary.BigEndian.PutUint64(b[5:], ms)
	return append(b, helloMAC(key, session, ms)...)
}

// ParseUDPHello returns the session and timestamp of a hello; verify with VerifyUDPHello.
func ParseUDPHello(b []byte) (session uint32, ms uint64, ok bool) {
	if len(b) != UDPHelloLen || b[0] != UDPHello {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(b[1:]), binary.BigEndian.Uint64(b[5:]), true
}

func VerifyUDPHello(b []byte, key [32]byte) bool {
	session, ms, ok := ParseUDPHello(b)
	return ok && hmac.Equal(b[13:], helloMAC(key, session, ms))
}

func UDPAckPacket(session uint32, ms uint64, observed netip.AddrPort) []byte {
	b := make([]byte, UDPAckLen)
	b[0] = UDPAck
	binary.BigEndian.PutUint32(b[1:], session)
	binary.BigEndian.PutUint64(b[5:], ms)
	ip := observed.Addr().As16()
	copy(b[13:], ip[:])
	binary.BigEndian.PutUint16(b[29:], observed.Port())
	return b
}

func ParseUDPAck(b []byte) (session uint32, ms uint64, observed netip.AddrPort, ok bool) {
	if len(b) != UDPAckLen || b[0] != UDPAck {
		return 0, 0, observed, false
	}
	ip := netip.AddrFrom16([16]byte(b[13:29])).Unmap()
	return binary.BigEndian.Uint32(b[1:]), binary.BigEndian.Uint64(b[5:]), netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[29:])), true
}

// AppendUDPSend appends a send datagram (header + packet) to dst.
func AppendUDPSend(dst []byte, session uint32, to [32]byte, pkt []byte) []byte {
	dst = append(dst, UDPSend, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(dst[len(dst)-4:], session)
	dst = append(dst, to[:]...)
	return append(dst, pkt...)
}

// SessionFrame is the FrameSession payload.
func SessionFrame(session uint32, key [32]byte) []byte {
	b := make([]byte, 36)
	binary.BigEndian.PutUint32(b, session)
	copy(b[4:], key[:])
	return b
}

func ParseSessionFrame(b []byte) (session uint32, key [32]byte, ok bool) {
	if len(b) != 36 {
		return 0, key, false
	}
	copy(key[:], b[4:])
	return binary.BigEndian.Uint32(b), key, true
}
