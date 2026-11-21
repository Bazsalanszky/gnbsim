// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package nas

import (
	"encoding/hex"
	"testing"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
)

// The UL NAS transport of gnbsim 03e43a5 for PDU session 10, an initial request, DNN internet and
// S-NSSAI 1/010203: an IPv4 PDU session.
const goldenIPv4UlNasTransport = "7e00670100142e0a01c1ffff917b000a80000a00000d00000300" +
	"120a81220401010203250908696e7465726e6574"

func goldenSnssai() *models.Snssai {
	sd := "010203"
	return &models.Snssai{Sst: 1, Sd: &sd}
}

func TestPduSessionEstablishmentRequestIPv4IsUnchanged(t *testing.T) {
	for name, build := range map[string]func() ([]byte, error){
		"old function": func() ([]byte, error) {
			return GetUlNasTransportPduSessionEstablishmentRequest(10,
				nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", goldenSnssai())
		},
		"WithType(IPv4)": func() ([]byte, error) {
			return GetUlNasTransportPduSessionEstablishmentRequestWithType(10,
				nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", goldenSnssai(), nasMessage.PDUSessionTypeIPv4)
		},
	} {
		got, err := build()
		if err != nil || hex.EncodeToString(got) != goldenIPv4UlNasTransport {
			t.Errorf("%s = %x, %v; want %s", name, got, err, goldenIPv4UlNasTransport)
		}
	}
}

func TestPduSessionEstablishmentRequestCarriesTheType(t *testing.T) {
	types := []uint8{
		nasMessage.PDUSessionTypeIPv4, nasMessage.PDUSessionTypeIPv6,
		nasMessage.PDUSessionTypeIPv4IPv6, nasMessage.PDUSessionTypeEthernet,
	}
	for _, want := range types {
		encoded, err := GetUlNasTransportPduSessionEstablishmentRequestWithType(10,
			nasMessage.ULNASTransportRequestTypeInitialRequest, "internet6", goldenSnssai(), want)
		if err != nil {
			t.Fatal(err)
		}
		m := nas.NewMessage()
		if err := m.PlainNasDecode(&encoded); err != nil {
			t.Fatal(err)
		}
		inner := m.ULNASTransport.GetPayloadContainerContents()
		sm := nas.NewMessage()
		if err := sm.PlainNasDecode(&inner); err != nil {
			t.Fatal(err)
		}
		if got := sm.PDUSessionEstablishmentRequest.GetPDUSessionTypeValue(); got != want {
			t.Errorf("PDU session type %d, want %d", got, want)
		}
	}
}
