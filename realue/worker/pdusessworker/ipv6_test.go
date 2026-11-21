// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

// what the tests give a session with IPv6: the interface identifier of its PDU address, the prefix
// the network advertises, the address the two form and where the echo requests go
var (
	testIID        = []byte{0x5e, 0xf3, 0xb5, 0xe1, 0x5f, 0x82, 0xdd, 0x04}
	testPrefix     = net.ParseIP("2a0e:8f02:f07b:500::")
	testUeAddr6    = net.ParseIP("2a0e:8f02:f07b:500:5ef3:b5e1:5f82:dd04")
	testRouterLL   = net.ParseIP("fe80::1")
	testDefaultAs6 = "fd35:6e6c:6162::254"
)

// raOption is a prefix information option (RFC 4861 clause 4.6.2).
func prefixInfo(prefix net.IP, prefixLen, flags byte, valid uint32) []byte {
	opt := make([]byte, optPrefixInfoLen)
	opt[0], opt[1], opt[2], opt[3] = optPrefixInfo, optPrefixInfoLen/8, prefixLen, flags
	binary.BigEndian.PutUint32(opt[4:8], valid)
	binary.BigEndian.PutUint32(opt[8:12], valid)
	copy(opt[16:], prefix.To16())
	return opt
}

// routerAdvertisement builds the IPv6 packet of a router advertisement carrying opts.
func routerAdvertisement(src, dst net.IP, hopLimit int, code byte, opts ...[]byte) []byte {
	msg := make([]byte, raFixedLen)
	msg[0], msg[1], msg[4] = byte(ipv6.ICMPTypeRouterAdvertisement), code, 64
	binary.BigEndian.PutUint16(msg[6:8], 1800)
	for _, opt := range opts {
		msg = append(msg, opt...)
	}
	binary.BigEndian.PutUint16(msg[2:4], icmpv6Checksum(src, dst, msg))
	return ipv6Packet(src, dst, hopLimit, msg)
}

func echoData(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(echoPayload)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func usableRA(dst net.IP) []byte {
	return routerAdvertisement(testRouterLL, dst, ndHopLimit, 0,
		prefixInfo(testPrefix, slaacPrefixLen, prefixFlagAutoconf|0x80, 3600))
}

func TestAddressesFromTheInterfaceID(t *testing.T) {
	if got := linkLocalAddress(testIID); !got.Equal(net.ParseIP("fe80::5ef3:b5e1:5f82:dd04")) {
		t.Errorf("link-local address %v", got)
	}
	if got := slaacAddress(testPrefix, testIID); !got.Equal(testUeAddr6) {
		t.Errorf("SLAAC address %v, want %v", got, testUeAddr6)
	}
}

// The router solicitation is what the SMF answers: hop limit 255, from the UE's link-local address
// to all routers, with no options, and a checksum the receiver accepts.
func TestBuildRouterSolicitation(t *testing.T) {
	src := linkLocalAddress(testIID)
	pkt := buildRouterSolicitation(src)
	want := "6000000000083aff" + "fe800000000000005ef3b5e15f82dd04" + "ff020000000000000000000000000002" +
		"85002bdb00000000" // the checksum computed independently of icmpv6Checksum
	if got := hex.EncodeToString(pkt); got != want {
		t.Fatalf("router solicitation\n got %s\nwant %s", got, want)
	}
	m, err := parseICMPv6(pkt)
	if err != nil {
		t.Fatalf("the solicitation does not parse: %v", err)
	}
	if m.icmpType() != ipv6.ICMPTypeRouterSolicitation || m.hopLimit != ndHopLimit {
		t.Errorf("type %v, hop limit %d", m.icmpType(), m.hopLimit)
	}
}

func TestBuildIcmpv6EchoRequest(t *testing.T) {
	pkt, err := buildIcmpv6EchoRequest(testUeAddr6, net.ParseIP(testDefaultAs6), 7, echoData(t))
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseICMPv6(pkt)
	if err != nil {
		t.Fatalf("the echo request does not parse: %v", err)
	}
	if m.icmpType() != ipv6.ICMPTypeEchoRequest || m.hopLimit != ueHopLimit ||
		!m.src.Equal(testUeAddr6) || !m.dst.Equal(net.ParseIP(testDefaultAs6)) {
		t.Errorf("type %v, hop limit %d, %v to %v", m.icmpType(), m.hopLimit, m.src, m.dst)
	}
	if id, seq := binary.BigEndian.Uint16(m.msg[4:6]), binary.BigEndian.Uint16(m.msg[6:8]); id != echoID || seq != 7 {
		t.Errorf("id %d, seq %d", id, seq)
	}
	if got := hex.EncodeToString(m.msg[8:]); got != echoPayload {
		t.Errorf("payload %s", got)
	}
}

func TestParseICMPv6Rejects(t *testing.T) {
	good := usableRA(allNodesMulticast)
	badSum := append([]byte(nil), good...)
	badSum[ipv6HeaderLen+2] ^= 0xff
	udp := append([]byte(nil), good...)
	udp[6] = 17
	v4 := append([]byte(nil), good...)
	v4[0] = 0x45
	long := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(long[4:6], uint16(len(good)))
	for name, pkt := range map[string][]byte{
		"short": good[:ipv6HeaderLen-1], "checksum": badSum, "UDP": udp, "version 4": v4,
		"payload length": long, "no ICMPv6 header": ipv6Packet(testRouterLL, allNodesMulticast, 255, []byte{134}),
	} {
		if _, err := parseICMPv6(pkt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// trailing octets past the payload length, as link layers pad, are not part of the message
	if m, err := parseICMPv6(append(good, 0, 0)); err != nil || len(m.msg) != len(good)-ipv6HeaderLen {
		t.Errorf("padded packet: %v", err)
	}
}

func TestParseRouterAdvertisement(t *testing.T) {
	ll := linkLocalAddress(testIID)
	slla := []byte{1, 1, 0, 0, 0, 0, 0, 1} // source link-layer address, before the prefix
	for _, tc := range []struct {
		err  error // errNoUsablePrefix, or nil for any other error
		name string
		pkt  []byte
		ok   bool
	}{
		{name: "solicited", ok: true, pkt: usableRA(ll)},
		{name: "after other options", ok: true, pkt: routerAdvertisement(testRouterLL, ll, 255, 0, slla,
			prefixInfo(net.ParseIP("2001:db8::"), 64, 0, 3600), // not autonomous: skipped
			prefixInfo(testPrefix, 64, prefixFlagAutoconf, 3600))},
		{name: "hop limit", pkt: routerAdvertisement(testRouterLL, ll, 64, 0, prefixInfo(testPrefix, 64, prefixFlagAutoconf, 1))},
		{name: "code", pkt: routerAdvertisement(testRouterLL, ll, 255, 1, prefixInfo(testPrefix, 64, prefixFlagAutoconf, 1))},
		{name: "global source", pkt: routerAdvertisement(testUeAddr6, ll, 255, 0, prefixInfo(testPrefix, 64, prefixFlagAutoconf, 1))},
		{name: "zero-length option", pkt: routerAdvertisement(testRouterLL, ll, 255, 0, []byte{1, 0, 0, 0, 0, 0, 0, 0})},
		{name: "option past the end", pkt: routerAdvertisement(testRouterLL, ll, 255, 0, []byte{3, 4, 64, 0x40, 0, 0, 0, 0})},
		{name: "prefix option length", pkt: routerAdvertisement(testRouterLL, ll, 255, 0, append([]byte{3, 3}, make([]byte, 22)...))},
		{name: "no options", err: errNoUsablePrefix, pkt: routerAdvertisement(testRouterLL, ll, 255, 0)},
		{name: "not autonomous", err: errNoUsablePrefix, pkt: routerAdvertisement(testRouterLL, ll, 255, 0, prefixInfo(testPrefix, 64, 0x80, 1))},
		{name: "/56", err: errNoUsablePrefix, pkt: routerAdvertisement(testRouterLL, ll, 255, 0, prefixInfo(testPrefix, 56, prefixFlagAutoconf, 1))},
		{name: "expired", err: errNoUsablePrefix, pkt: routerAdvertisement(testRouterLL, ll, 255, 0, prefixInfo(testPrefix, 64, prefixFlagAutoconf, 0))},
		{name: "link-local prefix", err: errNoUsablePrefix, pkt: routerAdvertisement(testRouterLL, ll, 255, 0, prefixInfo(net.ParseIP("fe80::"), 64, prefixFlagAutoconf, 1))},
	} {
		m, err := parseICMPv6(tc.pkt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		prefix, err := parseRouterAdvertisement(m)
		switch {
		case tc.ok:
			if err != nil || !prefix.Equal(testPrefix) {
				t.Errorf("%s: prefix %v, %v", tc.name, prefix, err)
			}
		case tc.err != nil:
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: %v, want %v", tc.name, err, tc.err)
			}
		case err == nil || errors.Is(err, errNoUsablePrefix):
			t.Errorf("%s: %v, want it refused", tc.name, err)
		}
	}
}
