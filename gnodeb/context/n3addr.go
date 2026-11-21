// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// N3 address families, as the n3PreferredFamily option names them.
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

// isIPv6Literal reports whether s is an IPv6 address (and not an IPv4 or IPv4-mapped one).
func isIPv6Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// N3Addresses returns the gNB's N3 address of each family, "" for a family it has none of.
//
// n3IpAddr may be of either family. n3Ipv6Addr adds an IPv6 address to an IPv4 n3IpAddr, for a
// dual-stack N3. An n3IpAddr that is not an IPv6 literal is returned as the IPv4 address, as
// before: an IPv4 address, or an empty value or a host name, which the user plane transport has
// always taken as it is.
func (gnb *GNodeB) N3Addresses() (ipv4, ipv6 string) {
	if isIPv6Literal(gnb.GnbN3Ip) {
		return "", gnb.GnbN3Ip
	}
	return gnb.GnbN3Ip, gnb.GnbN3Ipv6
}

// hasN3IPv4 reports whether the gNB can use IPv4 on N3. That is every configuration whose n3IpAddr
// is not an IPv6 address, which keeps the behaviour of a configuration from before IPv6 support.
func (gnb *GNodeB) hasN3IPv4() bool {
	return !isIPv6Literal(gnb.GnbN3Ip)
}

// ValidateN3 checks the N3 address options.
func (gnb *GNodeB) ValidateN3() error {
	if gnb.GnbN3Ipv6 != "" {
		if !isIPv6Literal(gnb.GnbN3Ipv6) {
			return fmt.Errorf("n3Ipv6Addr %q is not an IPv6 address", gnb.GnbN3Ipv6)
		}
		if isIPv6Literal(gnb.GnbN3Ip) {
			return fmt.Errorf("n3IpAddr %q is IPv6 already, n3Ipv6Addr %q would be a second one",
				gnb.GnbN3Ip, gnb.GnbN3Ipv6)
		}
	}
	switch strings.ToLower(gnb.N3PreferredFamily) {
	case "", FamilyIPv4, FamilyIPv6:
	default:
		return fmt.Errorf("n3PreferredFamily %q, want %s or %s",
			gnb.N3PreferredFamily, FamilyIPv4, FamilyIPv6)
	}
	return nil
}

// SelectN3Tunnel picks the address family of a PDU session's N3 tunnel from the UPF's uplink
// transport layer address (TS 38.414 clause 5.1: an IPv4 address, an IPv6 address, or both), and
// returns the UPF address to send to and the gNB's own address for the downlink F-TEID.
//
// With a single family, the gNB must have an address of it. With both (a 160-bit address, which an
// SMF sends for a dual-stack UPF), the gNB chooses: its preferred family when it has both, else the
// one it has. The SMF then follows the family of the downlink address the gNB returns.
func (gnb *GNodeB) SelectN3Tunnel(upfIPv4, upfIPv6 string) (upfIP, gnbIP string, err error) {
	gnbIPv4, gnbIPv6 := gnb.N3Addresses()
	hasIPv4, hasIPv6 := gnb.hasN3IPv4(), gnbIPv6 != ""
	var useIPv6 bool
	switch {
	case upfIPv4 != "" && upfIPv6 != "":
		switch {
		case hasIPv4 && hasIPv6:
			useIPv6 = strings.EqualFold(gnb.N3PreferredFamily, FamilyIPv6)
		case hasIPv6:
			useIPv6 = true
		case !hasIPv4:
			return "", "", errors.New("the gNB has no N3 address")
		}
	case upfIPv6 != "":
		if !hasIPv6 {
			return "", "", fmt.Errorf("the UPF's N3 address %s is IPv6, and the gNB has no IPv6 N3 address", upfIPv6)
		}
		useIPv6 = true
	case upfIPv4 != "":
		if !hasIPv4 {
			return "", "", fmt.Errorf("the UPF's N3 address %s is IPv4, and the gNB has no IPv4 N3 address", upfIPv4)
		}
	default:
		return "", "", errors.New("failed to resolve UPF IP address")
	}
	if useIPv6 {
		return upfIPv6, gnbIPv6, nil
	}
	return upfIPv4, gnbIPv4, nil
}
