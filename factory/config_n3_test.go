// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"testing"

	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
	profctx "github.com/omec-project/gnbsim/profile/context"
)

const (
	podV4 = "10.42.0.5"
	podV6 = "fd00::5"
)

func n3Config(singleInterface bool, n3, n3v6 string) *Config {
	return &Config{
		Info: &Info{Version: GNBSIM_EXPECTED_CONFIG_VERSION},
		Configuration: &Configuration{
			Gnbs:            map[string]*gnbctx.GNodeB{"gnb1": {GnbN3Ip: n3, GnbN3Ipv6: n3v6}},
			Profiles:        []*profctx.Profile{{Name: "profile1"}},
			SingleInterface: singleInterface,
		},
	}
}

func TestPodIPForN3(t *testing.T) {
	tests := []struct {
		name, podIP, podIPs, n3v6 string
		want, want6               string
	}{
		{name: "POD_IP IPv4, as before", podIP: podV4, want: podV4},
		{name: "POD_IP IPv6 (IPv6-only pod)", podIP: podV6, want: podV6},
		{name: "dual-stack POD_IPS, IPv4 first", podIP: podV4, podIPs: podV4 + "," + podV6, want: podV4},
		{name: "dual-stack POD_IPS, IPv6 first", podIP: podV6, podIPs: podV6 + "," + podV4, want: podV4},
		{name: "n3Ipv6Addr POD_IP, dual", podIP: podV6, podIPs: podV6 + ", " + podV4, n3v6: podIPKeyword, want: podV4, want6: podV6},
		{name: "n3Ipv6Addr POD_IP, IPv4-only pod", podIP: podV4, n3v6: podIPKeyword, want: podV4, want6: ""},
		{name: "n3Ipv6Addr POD_IP, IPv6-only pod", podIP: podV6, n3v6: podIPKeyword, want: podV6, want6: ""},
		{name: "no pod address", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(podIPKeyword, tc.podIP)
			t.Setenv("POD_IPS", tc.podIPs)
			c := n3Config(true, podIPKeyword, tc.n3v6)
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			gnb := c.Configuration.Gnbs["gnb1"]
			if gnb.GnbN3Ip != tc.want || gnb.GnbN3Ipv6 != tc.want6 {
				t.Errorf("n3IpAddr, n3Ipv6Addr = %q, %q, want %q, %q", gnb.GnbN3Ip, gnb.GnbN3Ipv6, tc.want, tc.want6)
			}
		})
	}
}

func TestPodIPIsOnlyReadInSingleInterfaceMode(t *testing.T) {
	t.Setenv(podIPKeyword, podV4)
	c := n3Config(false, "10.10.3.10", "")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.Configuration.Gnbs["gnb1"].GnbN3Ip; got != "10.10.3.10" {
		t.Errorf("n3IpAddr = %q", got)
	}
}

func TestValidateRejectsBadN3Options(t *testing.T) {
	for _, c := range []*Config{
		n3Config(false, "10.10.3.10", "10.10.3.11"),
		n3Config(false, "2001:db8::10", "2001:db8::11"),
	} {
		if err := c.Validate(); err == nil {
			gnb := c.Configuration.Gnbs["gnb1"]
			t.Errorf("Validate accepted n3IpAddr %q, n3Ipv6Addr %q", gnb.GnbN3Ip, gnb.GnbN3Ipv6)
		}
	}
	c := n3Config(false, "10.10.3.10", "2001:db8::10")
	c.Configuration.Gnbs["gnb1"].N3PreferredFamily = "both"
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted n3PreferredFamily both")
	}
}
