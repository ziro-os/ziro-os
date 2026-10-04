package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeGateway answers PCP or NAT-PMP on a loopback UDP port.
func fakeGateway(t *testing.T, proto string, ext netip.Addr) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	pcpPort = c.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 1100)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			switch {
			case proto == "pcp" && n == 60 && req[0] == 2 && req[1] == 1:
				resp := make([]byte, 60)
				resp[0], resp[1] = 2, 0x81
				binary.BigEndian.PutUint32(resp[4:], 7200)
				copy(resp[24:36], req[24:36]) // nonce
				resp[36] = 17
				copy(resp[40:42], req[40:42])
				binary.BigEndian.PutUint16(resp[42:], 61000)
				e := ext.As16()
				copy(resp[44:], e[:])
				c.WriteToUDP(resp, from)
			case proto == "nat-pmp" && n == 2 && req[1] == 0:
				resp := make([]byte, 12)
				resp[1] = 128
				e := ext.As4()
				copy(resp[8:], e[:])
				c.WriteToUDP(resp, from)
			case proto == "nat-pmp" && n == 12 && req[1] == 1:
				resp := make([]byte, 16)
				resp[1] = 129
				copy(resp[8:10], req[4:6])
				binary.BigEndian.PutUint16(resp[10:], 62000)
				binary.BigEndian.PutUint32(resp[12:], 7200)
				c.WriteToUDP(resp, from)
			}
		}
	}()
}

func TestPortMapPCPAndNATPMP(t *testing.T) {
	allowLoopGW = true
	defer func() { allowLoopGW, pcpPort = false, 5351 }()
	ext := netip.MustParseAddr("203.0.113.50")
	gw := netip.MustParseAddr("127.0.0.1")

	fakeGateway(t, "pcp", ext)
	m, err := mapPort(context.Background(), gw, 41641, nil, mapLease)
	if err != nil || m.proto != "pcp" || m.ext != netip.AddrPortFrom(ext, 61000) {
		t.Fatalf("pcp: %+v %v", m, err)
	}
	fakeGateway(t, "nat-pmp", ext)
	ssdpTarget = "127.0.0.1:9" // no UPnP here
	m, err = mapPort(context.Background(), gw, 41641, nil, mapLease)
	if err != nil || m.proto != "nat-pmp" || m.ext != netip.AddrPortFrom(ext, 62000) {
		t.Fatalf("nat-pmp: %+v %v", m, err)
	}
	if validGateway(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("a public gateway was accepted")
	}
}

// TestPortMapUPnP runs SSDP discovery, the device description and SOAP against a fake IGD.
func TestPortMapUPnP(t *testing.T) {
	allowLoopGW = true
	defer func() { allowLoopGW, pcpPort, ssdpTarget = false, 5351, "239.255.255.250:1900" }()
	pcpPort = 9 // nothing answers PCP / NAT-PMP
	var added string
	igd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/desc.xml":
			fmt.Fprint(w, `<?xml version="1.0"?><root><device><deviceList><device><deviceList><device><serviceList>`+
				`<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service>`+
				`</serviceList></device></deviceList></device></deviceList></device></root>`)
		case "/ctl":
			b, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(r.Header.Get("SOAPAction"), "#AddPortMapping"):
				added = string(b)
				fmt.Fprint(w, `<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>`)
			case strings.Contains(r.Header.Get("SOAPAction"), "#GetExternalIPAddress"):
				fmt.Fprint(w, `<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>198.51.100.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`)
			default:
				w.WriteHeader(500)
			}
		}
	}))
	defer igd.Close()
	ssdp, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer ssdp.Close()
	ssdpTarget = ssdp.LocalAddr().String()
	go func() {
		buf := make([]byte, 1500)
		n, from, err := ssdp.ReadFromUDP(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "M-SEARCH") {
			return
		}
		ssdp.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nLOCATION: "+igd.URL+"/desc.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"), from)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := mapPort(ctx, netip.MustParseAddr("127.0.0.1"), 41641, nil, mapLease)
	if err != nil || m.proto != "upnp" || m.ext != netip.MustParseAddrPort("198.51.100.9:41641") {
		t.Fatalf("upnp: %+v %v", m, err)
	}
	if !strings.Contains(added, "<NewProtocol>UDP</NewProtocol>") || !strings.Contains(added, "<NewInternalPort>41641</NewInternalPort>") {
		t.Fatalf("AddPortMapping: %s", added)
	}
}

func TestPathRankAndSpray(t *testing.T) {
	lan, v6, v4 := netip.MustParseAddrPort("192.168.1.5:1"), netip.MustParseAddrPort("[2001:db8::1]:1"), netip.MustParseAddrPort("203.0.113.1:1")
	ms := time.Millisecond
	if !betterPath(lan, 10*ms, v4, 9*ms) || betterPath(v4, 9*ms, lan, 10*ms) {
		t.Fatal("LAN must win within 20%")
	}
	if !betterPath(v6, 11*ms, v4, 10*ms) || betterPath(v6, 13*ms, v4, 10*ms) {
		t.Fatal("IPv6 allowance is 20%")
	}
	if betterPath(v4, 9*ms, v4, 10*ms) || !betterPath(v4, 7*ms, v4, 10*ms) {
		t.Fatal("same rank needs 20% better")
	}
	got := sprayTargets([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:40000"), v6, netip.MustParseAddrPort("127.0.0.1:5")})
	if len(got) != 2*sprayRadius || got[0].Port() != 40000-sprayRadius || got[0].Addr() != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("spray: %d targets, first %v", len(got), got[0])
	}
	if n := len(sprayTargets([]netip.AddrPort{netip.MustParseAddrPort("192.168.1.5:41641"), netip.MustParseAddrPort("100.64.0.9:41641")})); n != 4*sprayRadius {
		t.Fatalf("private (carrier-grade NAT) candidates must be probed too: %d", n)
	}
}

func TestNATTypeAndFailover(t *testing.T) {
	k, _, _ := newCurveKey()
	b, _ := NewMagicBind(k, nil, nil)
	b.mapped = map[string]netip.AddrPort{"r1/4": netip.MustParseAddrPort("198.51.100.1:5000")}
	if b.NATType() != "" {
		t.Fatal("one relay cannot tell")
	}
	b.mapped["r2/4"] = netip.MustParseAddrPort("198.51.100.1:5000")
	if b.NATType() != "easy" {
		t.Fatal("same port: easy")
	}
	b.mapped["r2/4"] = netip.MustParseAddrPort("198.51.100.1:5003")
	if b.NATType() != "hard" {
		t.Fatal("different ports: hard")
	}
	b.portMap = netip.MustParseAddrPort("198.51.100.1:41641")
	if b.NATType() != "easy" || b.PublicEndpoints()[0] != "198.51.100.1:41641" {
		t.Fatal("a mapped port makes it easy, and comes first")
	}

	// Three pings to the best path without a pong drop it to the relay.
	p := &mpeer{best: netip.MustParseAddrPort("198.51.100.7:41641"), bestUntil: time.Now().Add(trustBest), pings: map[[12]byte]pingSent{}}
	p.ep = &peerEP{p: p}
	b.peers[[32]byte{1}] = p
	b.open = true
	for i := 0; i < maxMissed; i++ {
		p.lastPing = time.Time{}
		b.pingPeer(p)
	}
	p.lastPing = time.Time{}
	b.pingPeer(p)
	if time.Now().Before(p.bestUntil) {
		t.Fatalf("best path kept after %d unanswered pings", p.missed)
	}
}

func TestNetSignature(t *testing.T) {
	if netSignature("none0") == "" {
		t.Skip("no interfaces")
	}
	first, second := netSignature("none0"), netSignature("none0")
	if first != second {
		t.Fatal("signature not stable: roaming would fire with no change")
	}
}
