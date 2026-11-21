// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	ipv6HeaderLen = 40
	protoICMPv6   = 58

	// RFC 4861 clause 4.1: a Router Solicitation and the Prefix Information option.
	rsLen              = 8
	raFixedLen         = 16 // type, code, checksum, hop limit, flags, lifetime, reachable, retrans
	optPrefixInfo      = 3
	optPrefixInfoLen   = 32
	prefixFlagAutoconf = 0x40

	// RFC 4861 clause 6.1: neighbour discovery messages are sent, and must arrive, with hop limit 255
	ndHopLimit = 255

	// slaacPrefixLen is the prefix length an interface identifier of 64 bits completes (RFC 4862
	// clause 5.5.3, TS 23.501 clause 5.8.2.2.2: the network gives the UE a /64)
	slaacPrefixLen = 64

	ueHopLimit = 64
)

// allRoutersMulticast is ff02::2, the destination of a Router Solicitation.
var allRoutersMulticast = net.ParseIP("ff02::2")

// linkLocalAddress is fe80::/64 with the interface identifier the network gave the UE in the PDU
// address (TS 23.501 clause 5.8.2.2.2).
func linkLocalAddress(interfaceID []byte) net.IP {
	ip := make(net.IP, net.IPv6len)
	ip[0], ip[1] = 0xfe, 0x80
	copy(ip[8:], interfaceID)
	return ip
}

// slaacAddress forms the UE's address from a /64 prefix and its interface identifier.
func slaacAddress(prefix net.IP, interfaceID []byte) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, prefix.To16()[:8])
	copy(ip[8:], interfaceID)
	return ip
}

// ipv6Packet prepends an IPv6 header to an ICMPv6 message.
func ipv6Packet(src, dst net.IP, hopLimit int, payload []byte) []byte {
	pkt := make([]byte, ipv6HeaderLen+len(payload))
	pkt[0] = 6 << 4 // version 6, traffic class 0, flow label 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = protoICMPv6
	pkt[7] = byte(hopLimit)
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	copy(pkt[ipv6HeaderLen:], payload)
	return pkt
}

// icmpv6Checksum is the ICMPv6 checksum over the IPv6 pseudo-header (RFC 8200 clause 8.1) and msg,
// whose checksum field must be zero.
func icmpv6Checksum(src, dst net.IP, msg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.To16())
	add(dst.To16())
	var lenAndNext [8]byte
	binary.BigEndian.PutUint32(lenAndNext[0:4], uint32(len(msg)))
	lenAndNext[7] = protoICMPv6
	add(lenAndNext[:])
	add(msg)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// buildRouterSolicitation returns an IPv6 Router Solicitation from the UE's link-local address to
// ff02::2. It has no source link-layer address option: the PDU session has no link layer.
func buildRouterSolicitation(src net.IP) []byte {
	rs := make([]byte, rsLen)
	rs[0] = byte(ipv6.ICMPTypeRouterSolicitation)
	binary.BigEndian.PutUint16(rs[2:4], icmpv6Checksum(src, allRoutersMulticast, rs))
	return ipv6Packet(src, allRoutersMulticast, ndHopLimit, rs)
}

// buildIcmpv6EchoRequest returns an IPv6 ICMPv6 echo request with the identifier of the IPv4 ones.
func buildIcmpv6EchoRequest(src, dst net.IP, seq int, data []byte) ([]byte, error) {
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{ID: echoID, Seq: seq, Data: data},
	}
	b, err := msg.Marshal(icmp.IPv6PseudoHeader(src, dst))
	if err != nil {
		return nil, err
	}
	return ipv6Packet(src, dst, ueHopLimit, b), nil
}

// icmpv6Message is an ICMPv6 message received by the UE, with the IPv6 header fields that matter.
type icmpv6Message struct {
	src, dst net.IP
	msg      []byte // type, code, checksum and body
	hopLimit int
}

func (m *icmpv6Message) icmpType() ipv6.ICMPType { return ipv6.ICMPType(m.msg[0]) }

// parseICMPv6 checks an IPv6 packet from the UPF and returns the ICMPv6 message it carries. Only
// ICMPv6 without extension headers is taken, which is all the network sends a UE here.
func parseICMPv6(pkt []byte) (*icmpv6Message, error) {
	if len(pkt) < ipv6HeaderLen {
		return nil, fmt.Errorf("IPv6 packet of %d octets", len(pkt))
	}
	if pkt[0]>>4 != 6 {
		return nil, fmt.Errorf("IP version %d, want 6", pkt[0]>>4)
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if ipv6HeaderLen+payloadLen > len(pkt) {
		return nil, fmt.Errorf("IPv6 payload length %d, the packet has %d octets after the header",
			payloadLen, len(pkt)-ipv6HeaderLen)
	}
	if next := pkt[6]; next != protoICMPv6 {
		return nil, fmt.Errorf("unsupported IPv6 next header: %d", next)
	}
	m := &icmpv6Message{
		src:      net.IP(pkt[8:24]),
		dst:      net.IP(pkt[24:40]),
		msg:      pkt[ipv6HeaderLen : ipv6HeaderLen+payloadLen],
		hopLimit: int(pkt[7]),
	}
	if len(m.msg) < 4 {
		return nil, fmt.Errorf("ICMPv6 message of %d octets", len(m.msg))
	}
	// the checksum covers the pseudo-header: a wrong one means the network built or rewrote the
	// packet wrongly, which is worth failing on in a test tool
	zeroed := append([]byte(nil), m.msg...)
	zeroed[2], zeroed[3] = 0, 0
	if got, want := binary.BigEndian.Uint16(m.msg[2:4]), icmpv6Checksum(m.src, m.dst, zeroed); got != want {
		return nil, fmt.Errorf("ICMPv6 checksum 0x%04x, want 0x%04x", got, want)
	}
	return m, nil
}

// errNoUsablePrefix marks a router advertisement without a prefix the UE can autoconfigure from.
var errNoUsablePrefix = errors.New("no autonomous /64 prefix")

// parseRouterAdvertisement validates a router advertisement (RFC 4861 clause 6.1.2) and returns
// the first prefix the UE can form its address from (RFC 4862 clause 5.5.3): autonomous flag set,
// /64, a non-zero valid lifetime and not link-local.
func parseRouterAdvertisement(m *icmpv6Message) (prefix net.IP, err error) {
	if m.hopLimit != ndHopLimit {
		return nil, fmt.Errorf("router advertisement with hop limit %d, want %d", m.hopLimit, ndHopLimit)
	}
	if code := m.msg[1]; code != 0 {
		return nil, fmt.Errorf("router advertisement with code %d", code)
	}
	if !m.src.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("router advertisement from %v, not a link-local address", m.src)
	}
	if len(m.msg) < raFixedLen {
		return nil, fmt.Errorf("router advertisement of %d octets", len(m.msg))
	}
	for opts := m.msg[raFixedLen:]; len(opts) > 0; {
		if len(opts) < 2 || opts[1] == 0 || int(opts[1])*8 > len(opts) {
			return nil, errors.New("router advertisement with a malformed option")
		}
		optLen := int(opts[1]) * 8
		opt := opts[:optLen]
		opts = opts[optLen:]
		if opt[0] != optPrefixInfo {
			continue
		}
		if optLen != optPrefixInfoLen {
			return nil, fmt.Errorf("prefix information option of %d octets", optLen)
		}
		p := net.IP(opt[16:32])
		if opt[2] != slaacPrefixLen || opt[3]&prefixFlagAutoconf == 0 ||
			binary.BigEndian.Uint32(opt[4:8]) == 0 || p.IsLinkLocalUnicast() {
			continue
		}
		return append(net.IP(nil), p...), nil
	}
	return nil, errNoUsablePrefix
}
