// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"go.yaml.in/yaml/v4"
)

func TestParsePduSessionType(t *testing.T) {
	tests := []struct {
		option string
		want   uint8
		ok     bool
	}{
		{"", nasMessage.PDUSessionTypeIPv4, true},
		{"IPv4", nasMessage.PDUSessionTypeIPv4, true},
		{"IPv6", nasMessage.PDUSessionTypeIPv6, true},
		{"IPv4v6", nasMessage.PDUSessionTypeIPv4IPv6, true},
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

func pduSessionProfile(t *testing.T, sessionType string) *Profile {
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
	p := &Profile{}
	if err := yaml.Unmarshal([]byte(in), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProfileInitReadsPduSessionType(t *testing.T) {
	for option, want := range map[string]uint8{
		"":       nasMessage.PDUSessionTypeIPv4, // the default, as before
		"IPv6":   nasMessage.PDUSessionTypeIPv6,
		"IPv4v6": nasMessage.PDUSessionTypeIPv4IPv6,
	} {
		p := pduSessionProfile(t, option)
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
