// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/omec-project/gnbsim/ngapconv"
	"github.com/omec-project/gnbsim/util/ngapTestpacket"
	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
)

// Encodings before IPv6 support (gnbsim 03e43a5) of one session (ID 10, DL TEID 0x11223344, QFI 1),
// AMF/RAN UE NGAP IDs 7/9 and the gNB N3 address 10.10.3.10.
const (
	goldenSetupResponseTransfer = "0003e00a0a030a112233440001"
	goldenSetupResponse         = "201d0024000003000a40020007005540020009004b401100000a0d0003e00a0a030a112233440001"
	goldenInitialCtxResponse    = "200e0024000003000a400200070055400200090048401100000a0d0003e00a0a030a112233440001"
)

const (
	gnbN3v4 = "10.10.3.10"
	gnbN3v6 = "2001:db8:630::10"
)

func goldenSession() *ngapTestpacket.PduSession {
	return &ngapTestpacket.PduSession{PduSessId: 10, Teid: 0x11223344, SuccessQfiList: []int64{1}, Success: true}
}

func TestIPv4SetupResponsesAreUnchanged(t *testing.T) {
	for _, gnbN3Ip := range []string{"", gnbN3v4} { // the session's own address, or the builder's
		ps := goldenSession()
		ps.GnbN3Ip = gnbN3Ip
		if got := hex.EncodeToString(ngapTestpacket.GetPDUSessionResourceSetupResponseTransfer(ps, gnbN3v4)); got != goldenSetupResponseTransfer {
			t.Errorf("transfer (session address %q) = %s, want %s", gnbN3Ip, got, goldenSetupResponseTransfer)
		}
		m, err := GetPDUSessionResourceSetupResponse([]*ngapTestpacket.PduSession{ps}, 7, 9, gnbN3v4)
		if err != nil || hex.EncodeToString(m) != goldenSetupResponse {
			t.Errorf("setup response (session address %q) = %x, %v", gnbN3Ip, m, err)
		}
		m, err = GetInitialContextSetupResponseForServiceRequest([]*ngapTestpacket.PduSession{ps}, 7, 9, gnbN3v4)
		if err != nil || hex.EncodeToString(m) != goldenInitialCtxResponse {
			t.Errorf("initial context setup response (session address %q) = %x, %v", gnbN3Ip, m, err)
		}
	}
}

func decodeDlTunnel(t *testing.T, encoded []byte) (ipv4, ipv6 string, bits uint64) {
	t.Helper()
	var transfer ngapType.PDUSessionResourceSetupResponseTransfer
	if err := aper.UnmarshalWithParams(encoded, &transfer, "valueExt"); err != nil {
		t.Fatalf("transfer does not decode: %v", err)
	}
	tunnel := transfer.DLQosFlowPerTNLInformation.UPTransportLayerInformation.GTPTunnel
	if tunnel == nil {
		t.Fatal("no GTP tunnel")
	}
	ipv4, ipv6 = ngapconv.IPAddressToString(tunnel.TransportLayerAddress)
	return ipv4, ipv6, tunnel.TransportLayerAddress.Value.BitLength
}

func TestSetupResponseTransferCarriesTheSessionsFamily(t *testing.T) {
	tests := []struct {
		name, builder, session string
		want4, want6           string
		bits                   uint64
	}{
		{"IPv6 session address", gnbN3v4, gnbN3v6, "", gnbN3v6, 128},
		{"IPv4 session address", gnbN3v6, "10.10.3.11", "10.10.3.11", "", 32},
		{"IPv6 builder address", gnbN3v6, "", "", gnbN3v6, 128},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := goldenSession()
			ps.GnbN3Ip = tc.session
			got4, got6, bits := decodeDlTunnel(t, ngapTestpacket.GetPDUSessionResourceSetupResponseTransfer(ps, tc.builder))
			if got4 != tc.want4 || got6 != tc.want6 || bits != tc.bits {
				t.Errorf("DL tunnel = %q %q (%d bits), want %q %q (%d bits)", got4, got6, bits, tc.want4, tc.want6, tc.bits)
			}
		})
	}
}

func TestIPAddressToNgapOneFamily(t *testing.T) {
	v4 := ngapconv.IPAddressToNgapOneFamily(gnbN3v4)
	if v4.Value.BitLength != 32 || !net.IP(v4.Value.Bytes).Equal(net.ParseIP(gnbN3v4)) {
		t.Errorf("IPv4: %+v", v4.Value)
	}
	v6 := ngapconv.IPAddressToNgapOneFamily("2001:db8::1")
	if v6.Value.BitLength != 128 || !net.IP(v6.Value.Bytes).Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("IPv6: %+v", v6.Value)
	}
	mapped := ngapconv.IPAddressToNgapOneFamily("::ffff:10.10.3.10")
	if mapped.Value.BitLength != 32 {
		t.Errorf("IPv4-mapped: %d bits, want 32", mapped.Value.BitLength)
	}
	if bad := ngapconv.IPAddressToNgapOneFamily("not-an-address"); bad.Value.BitLength != 0 {
		t.Errorf("not an address: %d bits, want 0 (as IPAddressToNgap)", bad.Value.BitLength)
	}
}
