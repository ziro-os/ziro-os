package daemon

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDNS(t *testing.T) {
	var d dnsServer
	d.set("office.ziro", map[string][]netip.Addr{"db-1": {netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("fd7a::3")}})
	check := func(name string, typ dnsmessage.Type, rcode dnsmessage.RCode, answers int) {
		t.Helper()
		var m dnsmessage.Message
		if err := m.Unpack(d.answer(query(t, name, typ))); err != nil {
			t.Fatal(err)
		}
		if m.Header.ID != 7 || m.Header.RCode != rcode || len(m.Answers) != answers {
			t.Fatalf("%s %v: rcode %v, %d answers", name, typ, m.Header.RCode, len(m.Answers))
		}
	}
	check("db-1.office.ziro.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, 1)
	check("DB-1.Office.Ziro.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, 1)
	check("nope.office.ziro.", dnsmessage.TypeA, dnsmessage.RCodeNameError, 0)
	check("example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, 0)
	if d.answer([]byte{1, 2, 3}) != nil {
		t.Fatal("answered garbage")
	}
}
