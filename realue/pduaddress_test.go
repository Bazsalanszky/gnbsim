// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package realue

import (
	"bytes"
	"net"
	"testing"

	"github.com/omec-project/gnbsim/common"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/nas/v2/security"
	"github.com/omec-project/openapi/v2/models"
)

var testIID = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

func pduAddress(sessionType uint8, length uint8, info ...byte) *nasType.PDUAddress {
	a := nasType.NewPDUAddress(nasMessage.PDUSessionEstablishmentAcceptPDUAddressType)
	a.SetLen(length)
	a.SetPDUSessionTypeValue(sessionType)
	var octets [12]uint8
	copy(octets[:], info)
	a.SetPDUAddressInformation(octets)
	return a
}

func TestDecodePduAddress(t *testing.T) {
	v4 := []byte{172, 250, 0, 1}
	dual := append(append([]byte{}, testIID...), v4...)
	tests := []struct {
		address     *nasType.PDUAddress
		name        string
		wantIPv4    net.IP
		wantIID     []byte
		sessionType uint8
		wantErr     bool
	}{
		{name: "IPv4", sessionType: nasMessage.PDUSessionTypeIPv4, address: pduAddress(1, 5, v4...), wantIPv4: net.IPv4(172, 250, 0, 1)},
		{name: "IPv6: the interface identifier", sessionType: nasMessage.PDUSessionTypeIPv6, address: pduAddress(2, 9, testIID...), wantIID: testIID},
		{
			name: "IPv4v6: identifier, then IPv4", sessionType: nasMessage.PDUSessionTypeIPv4IPv6, address: pduAddress(3, 13, dual...),
			wantIPv4: net.IPv4(172, 250, 0, 1), wantIID: testIID,
		},
		{name: "IPv4 too short", sessionType: nasMessage.PDUSessionTypeIPv4, address: pduAddress(1, 3, v4...), wantErr: true},
		{name: "IPv6 too short", sessionType: nasMessage.PDUSessionTypeIPv6, address: pduAddress(2, 5, testIID...), wantErr: true},
		{name: "IPv4v6 with an IPv6 length", sessionType: nasMessage.PDUSessionTypeIPv4IPv6, address: pduAddress(3, 9, testIID...), wantErr: true},
		{name: "type differs from the session", sessionType: nasMessage.PDUSessionTypeIPv4IPv6, address: pduAddress(1, 5, v4...), wantErr: true},
		{name: "no PDU address for IPv6", sessionType: nasMessage.PDUSessionTypeIPv6, wantErr: true},
		{name: "Ethernet has none", sessionType: nasMessage.PDUSessionTypeEthernet},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ipv4, iid, err := decodePduAddress(tc.sessionType, tc.address)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodePduAddress = %v, %x, want an error", ipv4, iid)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !ipv4.Equal(tc.wantIPv4) || !bytes.Equal(iid, tc.wantIID) {
				t.Errorf("decodePduAddress = %v, %x; want %v, %x", ipv4, iid, tc.wantIPv4, tc.wantIID)
			}
		})
	}
}

func TestFormatInterfaceID(t *testing.T) {
	if got := formatInterfaceID(testIID); got != "::1122:3344:5566:7788" {
		t.Errorf("formatInterfaceID = %q", got)
	}
}

func acceptMessage(sessionType uint8, address *nasType.PDUAddress) *common.UeMessage {
	accept := nasMessage.NewPDUSessionEstablishmentAccept(0)
	accept.SetPDUSessionType(sessionType)
	accept.SetSSCMode(1)
	accept.SetPDUSessionID(10)
	accept.PDUAddress = address
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.PDUSessionEstablishmentAccept = accept
	return &common.UeMessage{NasMsg: m}
}

func TestHandlePduSessEstAcceptEventByType(t *testing.T) {
	v4 := []byte{172, 250, 0, 7}
	dual := append(append([]byte{}, testIID...), v4...)
	tests := []struct {
		address     *nasType.PDUAddress
		name        string
		modelType   models.PduSessionType
		wantIPv4    net.IP
		wantIID     []byte
		sessionType uint8
	}{
		{
			name: "IPv4", sessionType: nasMessage.PDUSessionTypeIPv4, address: pduAddress(1, 5, v4...),
			modelType: models.PDUSESSIONTYPE_IPV4, wantIPv4: net.IPv4(172, 250, 0, 7),
		},
		{
			name: "IPv6", sessionType: nasMessage.PDUSessionTypeIPv6, address: pduAddress(2, 9, testIID...),
			modelType: models.PDUSESSIONTYPE_IPV6, wantIID: testIID,
		},
		{
			name: "IPv4v6", sessionType: nasMessage.PDUSessionTypeIPv4IPv6, address: pduAddress(3, 13, dual...),
			modelType: models.PDUSESSIONTYPE_IPV4_V6, wantIPv4: net.IPv4(172, 250, 0, 7), wantIID: testIID,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ue := realuectx.NewRealUe("imsi-208930100007500", security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
				nil, nil, "", "", "", "internet", nil)
			ue.PduSessionType = tc.sessionType
			if err := HandlePduSessEstAcceptEvent(ue, acceptMessage(tc.sessionType, tc.address)); err != nil {
				t.Fatalf("HandlePduSessEstAcceptEvent: %v", err)
			}
			sess, ok := ue.PduSessions[10]
			if !ok {
				t.Fatal("no PDU session 10")
			}
			if sess.PduSessType != tc.modelType || !sess.PduAddress.Equal(tc.wantIPv4) || !bytes.Equal(sess.Ipv6InterfaceId, tc.wantIID) {
				t.Errorf("session %s, %v, %x; want %s, %v, %x", sess.PduSessType, sess.PduAddress, sess.Ipv6InterfaceId,
					tc.modelType, tc.wantIPv4, tc.wantIID)
			}
		})
	}
}

func TestHandlePduSessEstAcceptEventRejectsAShortAddress(t *testing.T) {
	ue := realuectx.NewRealUe("imsi-208930100007500", security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		nil, nil, "", "", "", "internet", nil)
	if err := HandlePduSessEstAcceptEvent(ue, acceptMessage(nasMessage.PDUSessionTypeIPv4IPv6,
		pduAddress(3, 9, testIID...))); err == nil {
		t.Fatal("an IPv4v6 accept with an IPv6-length PDU address was taken")
	}
	if len(ue.PduSessions) != 0 {
		t.Error("a session was created from the malformed accept")
	}
}
