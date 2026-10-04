package router

import (
	"encoding/binary"
	"net/netip"
)

// Minimal STUN (RFC 5389) binding: devices send a request from their WireGuard socket and learn
// the public address and port the NAT mapped it to.

const stunMagic = 0x2112A442

// IsSTUN reports whether b looks like a STUN message (first two bits zero + magic cookie).
func IsSTUN(b []byte) bool {
	return len(b) >= 20 && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == stunMagic
}

// STUNRequest builds a binding request with transaction ID tx.
func STUNRequest(tx [12]byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], 0x0001)
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], tx[:])
	return b
}

// ParseSTUNRequest returns the transaction ID of a binding request.
func ParseSTUNRequest(b []byte) (tx [12]byte, ok bool) {
	if !IsSTUN(b) || binary.BigEndian.Uint16(b[0:]) != 0x0001 {
		return tx, false
	}
	copy(tx[:], b[8:20])
	return tx, true
}

// STUNResponse answers tx with the observed source address (XOR-MAPPED-ADDRESS).
func STUNResponse(tx [12]byte, from netip.AddrPort) []byte {
	ip := from.Addr().Unmap()
	alen, fam := 4, byte(1)
	if ip.Is6() {
		alen, fam = 16, 2
	}
	b := make([]byte, 20+4+4+alen)
	binary.BigEndian.PutUint16(b[0:], 0x0101)
	binary.BigEndian.PutUint16(b[2:], uint16(4+4+alen))
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], tx[:])
	a := b[20:]
	binary.BigEndian.PutUint16(a[0:], 0x0020)
	binary.BigEndian.PutUint16(a[2:], uint16(4+alen))
	a[5] = fam
	binary.BigEndian.PutUint16(a[6:], from.Port()^uint16(stunMagic>>16))
	key := b[4:20] // magic cookie + transaction ID
	raw := ip.AsSlice()
	for i := range raw {
		a[8+i] = raw[i] ^ key[i]
	}
	return b
}

// ParseSTUNResponse returns the transaction ID and mapped address of a binding success response.
func ParseSTUNResponse(b []byte) (tx [12]byte, addr netip.AddrPort, ok bool) {
	if !IsSTUN(b) || binary.BigEndian.Uint16(b[0:]) != 0x0101 {
		return tx, addr, false
	}
	copy(tx[:], b[8:20])
	n := int(binary.BigEndian.Uint16(b[2:]))
	if 20+n > len(b) {
		return tx, addr, false
	}
	key := b[4:20]
	for a := b[20 : 20+n]; len(a) >= 4; {
		typ, l := binary.BigEndian.Uint16(a[0:]), int(binary.BigEndian.Uint16(a[2:]))
		if 4+l > len(a) {
			break
		}
		v := a[4 : 4+l]
		if (typ == 0x0020 || typ == 0x0001) && len(v) >= 8 {
			alen := 4
			if v[1] == 2 {
				alen = 16
			}
			if len(v) >= 4+alen {
				port := binary.BigEndian.Uint16(v[2:])
				raw := make([]byte, alen)
				copy(raw, v[4:4+alen])
				if typ == 0x0020 {
					port ^= uint16(stunMagic >> 16)
					for i := range raw {
						raw[i] ^= key[i]
					}
				}
				if ip, ok2 := netip.AddrFromSlice(raw); ok2 {
					return tx, netip.AddrPortFrom(ip.Unmap(), port), true
				}
			}
		}
		pad := (l + 3) &^ 3
		if 4+pad > len(a) {
			break
		}
		a = a[4+pad:]
	}
	return tx, addr, false
}
