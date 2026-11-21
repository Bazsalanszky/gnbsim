// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"go.yaml.in/yaml/v4"
)

const (
	gnbV4  = "10.10.3.10"
	gnbV6  = "2001:db8:630::10"
	upfV4  = "10.10.3.1"
	upfV6  = "2001:db8:630::1"
	upfV6b = "2001:db8:630::2"
)

func TestN3Addresses(t *testing.T) {
	tests := []struct {
		name, n3, n3v6, want4, want6 string
	}{
		{"IPv4", gnbV4, "", gnbV4, ""},
		{"IPv6 in n3IpAddr", gnbV6, "", "", gnbV6},
		{"dual-stack", gnbV4, gnbV6, gnbV4, gnbV6},
		{"empty, as before", "", "", "", ""},
		{"host name, as before", "gnb.example", "", "gnb.example", ""},
		{"IPv4-mapped is IPv4", "::ffff:10.10.3.10", "", "::ffff:10.10.3.10", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gnb := &GNodeB{GnbN3Ip: tc.n3, GnbN3Ipv6: tc.n3v6}
			got4, got6 := gnb.N3Addresses()
			if got4 != tc.want4 || got6 != tc.want6 {
				t.Errorf("N3Addresses() = %q, %q, want %q, %q", got4, got6, tc.want4, tc.want6)
			}
		})
	}
}

func TestValidateN3(t *testing.T) {
	tests := []struct {
		name, n3, n3v6, pref string
		ok                   bool
	}{
		{"IPv4 only", gnbV4, "", "", true},
		{"dual, prefer IPv6", gnbV4, gnbV6, FamilyIPv6, true},
		{"dual, prefer IPv4, any case", gnbV4, gnbV6, "IPv4", true},
		{"n3Ipv6Addr is IPv4", gnbV4, "10.10.3.11", "", false},
		{"n3Ipv6Addr is IPv4-mapped", gnbV4, "::ffff:10.10.3.11", "", false},
		{"n3Ipv6Addr is not an address", gnbV4, "gnb6.example", "", false},
		{"two IPv6 addresses", gnbV6, "2001:db8:630::11", "", false},
		{"unknown family", gnbV4, gnbV6, "ipv5", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gnb := &GNodeB{GnbN3Ip: tc.n3, GnbN3Ipv6: tc.n3v6, N3PreferredFamily: tc.pref}
			if err := gnb.ValidateN3(); (err == nil) != tc.ok {
				t.Errorf("ValidateN3() = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestSelectN3Tunnel(t *testing.T) {
	tests := []struct {
		name             string
		n3, n3v6, pref   string
		upf4, upf6       string
		wantUpf, wantGnb string
		wantErr          bool
	}{
		// a 32-bit transport layer address, as before
		{name: "IPv4 UPF, IPv4 gNB", n3: gnbV4, upf4: upfV4, wantUpf: upfV4, wantGnb: gnbV4},
		{name: "IPv4 UPF, dual gNB", n3: gnbV4, n3v6: gnbV6, pref: FamilyIPv6, upf4: upfV4, wantUpf: upfV4, wantGnb: gnbV4},
		{name: "IPv4 UPF, IPv6 gNB", n3: gnbV6, upf4: upfV4, wantErr: true},
		// 128 bits
		{name: "IPv6 UPF, IPv6 gNB", n3: gnbV6, upf6: upfV6, wantUpf: upfV6, wantGnb: gnbV6},
		{name: "IPv6 UPF, dual gNB", n3: gnbV4, n3v6: gnbV6, upf6: upfV6, wantUpf: upfV6, wantGnb: gnbV6},
		{name: "IPv6 UPF, IPv4 gNB", n3: gnbV4, upf6: upfV6, wantErr: true},
		// 160 bits: the gNB chooses
		{name: "dual UPF, IPv4 gNB", n3: gnbV4, upf4: upfV4, upf6: upfV6, wantUpf: upfV4, wantGnb: gnbV4},
		{name: "dual UPF, IPv6 gNB", n3: gnbV6, upf4: upfV4, upf6: upfV6, wantUpf: upfV6, wantGnb: gnbV6},
		{name: "dual UPF, dual gNB, default IPv4", n3: gnbV4, n3v6: gnbV6, upf4: upfV4, upf6: upfV6, wantUpf: upfV4, wantGnb: gnbV4},
		{name: "dual UPF, dual gNB, prefer IPv4", n3: gnbV4, n3v6: gnbV6, pref: "ipv4", upf4: upfV4, upf6: upfV6, wantUpf: upfV4, wantGnb: gnbV4},
		{name: "dual UPF, dual gNB, prefer IPv6", n3: gnbV4, n3v6: gnbV6, pref: "IPv6", upf4: upfV4, upf6: upfV6b, wantUpf: upfV6b, wantGnb: gnbV6},
		// an n3IpAddr that is not an IPv6 literal keeps working as an IPv4 one
		{name: "empty n3IpAddr, IPv4 UPF", upf4: upfV4, wantUpf: upfV4, wantGnb: ""},
		{name: "no UPF address", n3: gnbV4, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gnb := &GNodeB{GnbN3Ip: tc.n3, GnbN3Ipv6: tc.n3v6, N3PreferredFamily: tc.pref}
			upf, own, err := gnb.SelectN3Tunnel(tc.upf4, tc.upf6)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SelectN3Tunnel() = %q, %q, want an error", upf, own)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectN3Tunnel() error: %v", err)
			}
			if upf != tc.wantUpf || own != tc.wantGnb {
				t.Errorf("SelectN3Tunnel() = %q, %q, want %q, %q", upf, own, tc.wantUpf, tc.wantGnb)
			}
		})
	}
}

func TestGNodeBYAMLReadsN3Options(t *testing.T) {
	var gnb GNodeB
	in := "n3IpAddr: " + gnbV4 + "\nn3Ipv6Addr: " + gnbV6 + "\nn3PreferredFamily: ipv6\nn3Port: 2152\n"
	if err := yaml.Unmarshal([]byte(in), &gnb); err != nil {
		t.Fatal(err)
	}
	if gnb.GnbN3Ip != gnbV4 || gnb.GnbN3Ipv6 != gnbV6 || gnb.N3PreferredFamily != FamilyIPv6 || gnb.GnbN3Port != 2152 {
		t.Errorf("decoded %q %q %q %d", gnb.GnbN3Ip, gnb.GnbN3Ipv6, gnb.N3PreferredFamily, gnb.GnbN3Port)
	}
}
