// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"go.yaml.in/yaml/v4"
)

// the pduSessionType options and the defaultAsV6 the tests use
const (
	optIPv4         = "IPv4"
	optIPv6         = "IPv6"
	optIPv4v6       = "IPv4v6"
	testDefaultAsV6 = "2001:db8::6"
)

func TestParsePduSessionType(t *testing.T) {
	tests := []struct {
		option string
		want   uint8
		ok     bool
	}{
		{"", nasMessage.PDUSessionTypeIPv4, true},
		{optIPv4, nasMessage.PDUSessionTypeIPv4, true},
		{optIPv6, nasMessage.PDUSessionTypeIPv6, true},
		{optIPv4v6, nasMessage.PDUSessionTypeIPv4IPv6, true},
		{"ipv4V6", nasMessage.PDUSessionTypeIPv4IPv6, true},
		{"Ethernet", nasMessage.PDUSessionTypeEthernet, true},
		{"Unstructured", nasMessage.PDUSessionTypeUnstructured, true},
		{"IPv4IPv6", 0, false},
		{"dual", 0, false},
	}
	for _, tc := range tests {
		got, err := ParsePduSessionType(tc.option)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParsePduSessionType(%q) = %d, %v; want %d, ok %v", tc.option, got, err, tc.want, tc.ok)
		}
	}
}

func pduSessionProfile(t *testing.T, sessionType string, more ...string) *Profile {
	t.Helper()
	in := `profileType: pdusessest
profileName: p
gnbName: gnb1
startImsi: "208930100007500"
ueCount: 1
dnn: internet
sNssai: {sst: 1, sd: "010203"}
`
	if sessionType != "" {
		in += "pduSessionType: " + sessionType + "\n"
	}
	for _, line := range more {
		in += line + "\n"
	}
	p := &Profile{}
	if err := yaml.Unmarshal([]byte(in), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProfileInitReadsPduSessionType(t *testing.T) {
	for option, want := range map[string]uint8{
		"":        nasMessage.PDUSessionTypeIPv4, // the default, as before
		optIPv6:   nasMessage.PDUSessionTypeIPv6,
		optIPv4v6: nasMessage.PDUSessionTypeIPv4IPv6,
	} {
		p := pduSessionProfile(t, option, "defaultAsV6: "+testDefaultAsV6)
		if err := p.Init(); err != nil {
			t.Fatalf("pduSessionType %q: Init: %v", option, err)
		}
		if p.NasPduSessionType != want {
			t.Errorf("pduSessionType %q: NAS value %d, want %d", option, p.NasPduSessionType, want)
		}
	}
	if err := pduSessionProfile(t, "IPv7").Init(); err == nil {
		t.Error("Init accepted pduSessionType IPv7")
	}
}

func TestProfileInitChecksDefaultAsV6(t *testing.T) {
	for _, tc := range []struct {
		sessionType, defaultAsV6 string
		ok                       bool
	}{
		{"", "", true},                   // IPv4 needs none
		{optIPv4, testDefaultAsV6, true}, // and has no use for one
		{optIPv6, testDefaultAsV6, true},
		{optIPv4v6, testDefaultAsV6, true},
		{optIPv6, "", false}, // there is nothing to default to
		{optIPv4v6, "", false},
		{optIPv6, "192.168.250.1", false},
		{optIPv6, "::ffff:192.168.250.1", false}, // an IPv4 address in IPv6 notation
		{optIPv4, "not-an-address", false},
	} {
		var more []string
		if tc.defaultAsV6 != "" {
			more = append(more, "defaultAsV6: \""+tc.defaultAsV6+"\"")
		}
		p := pduSessionProfile(t, tc.sessionType, more...)
		if err := p.Init(); (err == nil) != tc.ok {
			t.Errorf("pduSessionType %q, defaultAsV6 %q: Init: %v", tc.sessionType, tc.defaultAsV6, err)
		} else if err == nil && p.DefaultAsV6 != tc.defaultAsV6 {
			t.Errorf("defaultAsV6 read as %q", p.DefaultAsV6)
		}
	}
}
