package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Port mapping: ask the local router to forward our WireGuard UDP port, the way ZeroTier does.
// A mapped port turns the hardest home NAT into a reachable address. Tried in order: PCP (RFC
// 6887), NAT-PMP (RFC 6886), UPnP IGD (SSDP + SOAP AddPortMapping). Only the default gateway, and
// only one on a private address, is ever asked; responses are size-limited; the mapping covers
// our UDP port only, lasts 2 hours, is renewed at half-life and removed when zirocd stops.

const (
	mapLease   = 2 * time.Hour
	mapTimeout = 2 * time.Second
	mapMaxBody = 64 << 10
)

// Test hooks: real gateways listen on the standard ports.
var (
	pcpPort      = 5351
	ssdpTarget   = "239.255.255.250:1900"
	allowLoopGW  = false // tests run their fake gateway on 127.0.0.1
	mapHTTP      = &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	gatewayProbe = defaultGateway
)

type portMapping struct {
	proto    string // "pcp", "nat-pmp", "upnp"
	ext      netip.AddrPort
	expires  time.Time
	gw       netip.Addr
	internal uint16
	upnp     *upnpService // for renewal and removal
}

func validGateway(gw netip.Addr) bool {
	return gw.Is4() && (gw.IsPrivate() || (allowLoopGW && gw.IsLoopback()))
}

// localAddrTo is our address on the gateway's network (where its mappings point).
func localAddrTo(gw netip.Addr) (netip.Addr, error) {
	c, err := net.Dial("udp4", netip.AddrPortFrom(gw, 9).String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// mapPort asks the gateway, protocol by protocol, to map our UDP port (lifetime 0 removes it).
func mapPort(ctx context.Context, gw netip.Addr, port uint16, prev *portMapping, lifetime time.Duration) (*portMapping, error) {
	if !validGateway(gw) {
		return nil, fmt.Errorf("gateway %s is not a private address: not asking it", gw)
	}
	local, err := localAddrTo(gw)
	if err != nil {
		return nil, err
	}
	var errs []string
	if m, err := pcpMap(gw, local, port, lifetime); err == nil {
		return m, nil
	} else {
		errs = append(errs, "pcp: "+err.Error())
	}
	if m, err := natpmpMap(gw, port, lifetime); err == nil {
		return m, nil
	} else {
		errs = append(errs, "nat-pmp: "+err.Error())
	}
	if m, err := upnpMap(ctx, gw, local, port, prev, lifetime); err == nil {
		return m, nil
	} else {
		errs = append(errs, "upnp: "+err.Error())
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

// udpExchange sends req to gw:port and returns the first answer from that exact address.
func udpExchange(gw netip.Addr, port int, req []byte, check func([]byte) bool) ([]byte, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(gw, uint16(port)))
	buf := make([]byte, 1100)
	for try := 0; try < 2; try++ {
		if _, err := c.WriteToUDP(req, to); err != nil {
			return nil, err
		}
		_ = c.SetReadDeadline(time.Now().Add(mapTimeout / 2))
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if from.AddrPort().Addr().Unmap() == gw && check(buf[:n]) {
				return buf[:n], nil
			}
		}
	}
	return nil, errors.New("no answer")
}

// ---- PCP (RFC 6887) ----

func pcpMap(gw, local netip.Addr, port uint16, lifetime time.Duration) (*portMapping, error) {
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	req := make([]byte, 60)
	req[0], req[1] = 2, 1 // version 2, MAP
	binary.BigEndian.PutUint32(req[4:], uint32(lifetime/time.Second))
	l16 := local.As16()
	copy(req[8:24], l16[:])
	copy(req[24:36], nonce[:])
	req[36] = 17 // UDP
	binary.BigEndian.PutUint16(req[40:], port)
	binary.BigEndian.PutUint16(req[42:], port) // suggest the same external port
	resp, err := udpExchange(gw, pcpPort, req, func(b []byte) bool {
		return len(b) >= 60 && b[0] == 2 && b[1] == 0x81 && bytes.Equal(b[24:36], nonce[:])
	})
	if err != nil {
		return nil, err
	}
	if resp[3] != 0 {
		return nil, fmt.Errorf("result code %d", resp[3])
	}
	ip := netip.AddrFrom16([16]byte(resp[44:60])).Unmap()
	ext := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(resp[42:]))
	life := time.Duration(binary.BigEndian.Uint32(resp[4:])) * time.Second
	return &portMapping{proto: "pcp", ext: ext, expires: time.Now().Add(life), gw: gw, internal: port}, nil
}

// ---- NAT-PMP (RFC 6886) ----

func natpmpMap(gw netip.Addr, port uint16, lifetime time.Duration) (*portMapping, error) {
	addrResp, err := udpExchange(gw, pcpPort, []byte{0, 0}, func(b []byte) bool { return len(b) >= 12 && b[0] == 0 && b[1] == 128 })
	if err != nil {
		return nil, err
	}
	if code := binary.BigEndian.Uint16(addrResp[2:]); code != 0 {
		return nil, fmt.Errorf("result code %d", code)
	}
	extIP := netip.AddrFrom4([4]byte(addrResp[8:12]))
	req := make([]byte, 12)
	req[1] = 1 // map UDP
	binary.BigEndian.PutUint16(req[4:], port)
	binary.BigEndian.PutUint16(req[6:], port)
	binary.BigEndian.PutUint32(req[8:], uint32(lifetime/time.Second))
	resp, err := udpExchange(gw, pcpPort, req, func(b []byte) bool {
		return len(b) >= 16 && b[0] == 0 && b[1] == 129 && binary.BigEndian.Uint16(b[8:]) == port
	})
	if err != nil {
		return nil, err
	}
	if code := binary.BigEndian.Uint16(resp[2:]); code != 0 {
		return nil, fmt.Errorf("result code %d", code)
	}
	life := time.Duration(binary.BigEndian.Uint32(resp[12:])) * time.Second
	ext := netip.AddrPortFrom(extIP, binary.BigEndian.Uint16(resp[10:]))
	return &portMapping{proto: "nat-pmp", ext: ext, expires: time.Now().Add(life), gw: gw, internal: port}, nil
}

// ---- UPnP IGD ----

type upnpService struct {
	control string // absolute control URL on the gateway
	typ     string // urn:schemas-upnp-org:service:WANIPConnection:1 (or :2, or WANPPPConnection:1)
	extPort uint16
}

// upnpDiscover finds the gateway's WAN connection service: SSDP M-SEARCH, answers only from the
// gateway, description fetched only from the gateway's own address.
func upnpDiscover(ctx context.Context, gw netip.Addr) (*upnpService, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 1\r\n\r\n"
	for _, t := range []string{ssdpTarget, netip.AddrPortFrom(gw, 1900).String()} {
		if ua, err := net.ResolveUDPAddr("udp4", t); err == nil {
			_, _ = c.WriteToUDP([]byte(msg), ua)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(mapTimeout))
	buf := make([]byte, 2048)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return nil, errors.New("no UPnP gateway answered")
		}
		if from.AddrPort().Addr().Unmap() != gw && !(allowLoopGW && from.AddrPort().Addr().Unmap().IsLoopback()) {
			continue
		}
		var loc string
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
				loc = strings.TrimSpace(v)
			}
		}
		u, err := url.Parse(loc)
		if err != nil || u.Scheme != "http" {
			continue
		}
		if h, err := netip.ParseAddr(u.Hostname()); err != nil || h != gw {
			continue // the description must come from the gateway itself
		}
		return upnpDescribe(ctx, u)
	}
}

type upnpDesc struct {
	URLBase string         `xml:"URLBase"`
	Device  upnpDescDevice `xml:"device"`
}

type upnpDescDevice struct {
	Services []struct {
		Type    string `xml:"serviceType"`
		Control string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []upnpDescDevice `xml:"deviceList>device"`
}

func upnpDescribe(ctx context.Context, loc *url.URL) (*upnpService, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
	resp, err := mapHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d upnpDesc
	if err := xml.NewDecoder(io.LimitReader(resp.Body, mapMaxBody)).Decode(&d); err != nil {
		return nil, fmt.Errorf("description: %w", err)
	}
	base := loc
	if d.URLBase != "" {
		if u, err := url.Parse(d.URLBase); err == nil && u.Host == loc.Host {
			base = u
		}
	}
	var walk func(dev upnpDescDevice) *upnpService
	walk = func(dev upnpDescDevice) *upnpService {
		for _, s := range dev.Services {
			if strings.Contains(s.Type, ":WANIPConnection:") || strings.Contains(s.Type, ":WANPPPConnection:") {
				ctl, err := base.Parse(s.Control)
				if err == nil && ctl.Host == loc.Host && ctl.Scheme == "http" {
					return &upnpService{control: ctl.String(), typ: strings.TrimSpace(s.Type)}
				}
			}
		}
		for _, sub := range dev.Devices {
			if s := walk(sub); s != nil {
				return s
			}
		}
		return nil
	}
	if s := walk(d.Device); s != nil {
		return s, nil
	}
	return nil, errors.New("no WAN connection service")
}

func (s *upnpService) soap(ctx context.Context, action, args string) (string, error) {
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + s.typ + `">` +
		args + `</u:` + action + `></s:Body></s:Envelope>`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.control, strings.NewReader(body))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+s.typ+"#"+action+`"`)
	resp, err := mapHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, mapMaxBody))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", action, resp.StatusCode)
	}
	return string(b), nil
}

func xmlField(doc, name string) string {
	d := xml.NewDecoder(strings.NewReader(doc))
	for {
		t, err := d.Token()
		if err != nil {
			return ""
		}
		if se, ok := t.(xml.StartElement); ok && se.Name.Local == name {
			var v string
			if d.DecodeElement(&v, &se) == nil {
				return strings.TrimSpace(v)
			}
		}
	}
}

func upnpMap(ctx context.Context, gw, local netip.Addr, port uint16, prev *portMapping, lifetime time.Duration) (*portMapping, error) {
	var svc *upnpService
	if prev != nil && prev.upnp != nil && prev.gw == gw {
		svc = prev.upnp
	} else {
		var err error
		if svc, err = upnpDiscover(ctx, gw); err != nil {
			return nil, err
		}
	}
	if lifetime == 0 {
		_, err := svc.soap(ctx, "DeletePortMapping", fmt.Sprintf(
			"<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol>", svc.extPort))
		return nil, err
	}
	ext := port
	if svc.extPort != 0 {
		ext = svc.extPort
	}
	add := func(p uint16) error {
		_, err := svc.soap(ctx, "AddPortMapping", fmt.Sprintf(
			"<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol>"+
				"<NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"+
				"<NewPortMappingDescription>zirocd</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>",
			p, port, local, int(lifetime/time.Second)))
		return err
	}
	if err := add(ext); err != nil { // the port is taken (another device): any other one
		var r [2]byte
		_, _ = rand.Read(r[:])
		ext = 20000 + binary.BigEndian.Uint16(r[:])%40000
		if err := add(ext); err != nil {
			return nil, err
		}
	}
	svc.extPort = ext
	resp, err := svc.soap(ctx, "GetExternalIPAddress", "")
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(xmlField(resp, "NewExternalIPAddress"))
	if err != nil || !ip.Is4() {
		return nil, errors.New("gateway reported no external address")
	}
	return &portMapping{proto: "upnp", ext: netip.AddrPortFrom(ip, ext), expires: time.Now().Add(lifetime), gw: gw, internal: port, upnp: svc}, nil
}

// ---- lifecycle ----

// runPortMapper keeps a mapping of our UDP port alive while ctx lives, telling the bind about
// it, and removes it on exit.
func runPortMapper(ctx context.Context, b *MagicBind, port uint16) {
	var cur *portMapping
	defer func() {
		if cur != nil {
			dctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = mapPort(dctx, cur.gw, port, cur, 0)
			cancel()
			b.SetPortMapping(netip.AddrPort{}, "")
		}
	}()
	for {
		gw, err := gatewayProbe()
		needed := cur == nil || cur.gw != gw || time.Until(cur.expires) < mapLease/2
		if err == nil && needed {
			mctx, cancel := context.WithTimeout(ctx, 3*mapTimeout)
			m, err := mapPort(mctx, gw, port, cur, mapLease)
			cancel()
			// A private external address (carrier-grade or double NAT) is still kept: peers on the
			// same upstream network can use it, and a dead candidate only costs a few pings.
			if err == nil && m.ext.Addr().IsGlobalUnicast() {
				cur = m
				b.SetPortMapping(m.ext, m.proto)
			} else if cur != nil && cur.gw != gw { // moved to a network without port mapping
				cur = nil
				b.SetPortMapping(netip.AddrPort{}, "")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}
