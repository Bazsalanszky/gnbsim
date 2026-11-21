// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package gnbcpueworker

import (
	"testing"

	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
	"github.com/omec-project/gnbsim/ngapconv"
	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/util/idgenerator"
)

const (
	tGnb4 = "10.10.3.10"
	tGnb6 = "2001:db8::10"
	tUpf4 = "10.10.3.1"
	tUpf6 = "2001:db8::1"
)

// setupItem builds a PDU Session Resource Setup item whose uplink tunnel is at upf4 and/or upf6.
func setupItem(t *testing.T, upf4, upf6 string) pduSessResourceSetupItem {
	t.Helper()
	transfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
	add := func(ie ngapType.PDUSessionResourceSetupRequestTransferIEs) {
		transfer.ProtocolIEs.List = append(transfer.ProtocolIEs.List, ie)
	}
	add(ngapType.PDUSessionResourceSetupRequestTransferIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDULNGUUPTNLInformation},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
			Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentULNGUUPTNLInformation,
			ULNGUUPTNLInformation: &ngapType.UPTransportLayerInformation{
				Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
				GTPTunnel: &ngapType.GTPTunnel{
					TransportLayerAddress: ngapconv.IPAddressToNgap(upf4, upf6),
					GTPTEID:               ngapType.GTPTEID{Value: aper.OctetString{0, 0, 0, 1}},
				},
			},
		},
	})
	add(ngapType.PDUSessionResourceSetupRequestTransferIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionType},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
			Present:        ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionType,
			PDUSessionType: &ngapType.PDUSessionType{Value: ngapType.PDUSessionTypePresentIpv4v6},
		},
	})
	add(ngapType.PDUSessionResourceSetupRequestTransferIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDQosFlowSetupRequestList},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
		Value: ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
			Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentQosFlowSetupRequestList,
			QosFlowSetupRequestList: &ngapType.QosFlowSetupRequestList{List: []ngapType.QosFlowSetupRequestItem{{
				QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1},
				QosFlowLevelQosParameters: ngapType.QosFlowLevelQosParameters{
					QosCharacteristics: ngapType.QosCharacteristics{
						Present:       ngapType.QosCharacteristicsPresentNonDynamic5QI,
						NonDynamic5QI: &ngapType.NonDynamic5QIDescriptor{FiveQI: ngapType.FiveQI{Value: 9}},
					},
					AllocationAndRetentionPriority: ngapType.AllocationAndRetentionPriority{
						PriorityLevelARP: ngapType.PriorityLevelARP{Value: 8},
					},
				},
			}}},
		},
	})
	encoded, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		t.Fatalf("encode the transfer: %v", err)
	}
	return pduSessResourceSetupItem{
		PDUSessionID:                           ngapType.PDUSessionID{Value: 1},
		SNSSAI:                                 ngapType.SNSSAI{SST: ngapType.SST{Value: aper.OctetString{1}}},
		PDUSessionResourceSetupRequestTransfer: encoded,
	}
}

func n3TestGnbUe(n3, n3v6, pref string) *gnbctx.GnbCpUe {
	gnb := &gnbctx.GNodeB{
		GnbN3Ip: n3, GnbN3Ipv6: n3v6, N3PreferredFamily: pref,
		GnbUes:          gnbctx.NewGnbUeDao(),
		GnbPeers:        gnbctx.NewGnbPeerDao(),
		DlTeidGenerator: idgenerator.NewGenerator(1, 100),
	}
	return gnbctx.NewGnbCpUe(1, gnb, nil)
}

// The gNB picks the tunnel's family from the UPF's address and its own, and answers with its own
// address of that family.
func TestSetupPduSessionPicksTheN3Family(t *testing.T) {
	tests := []struct {
		name, n3, n3v6, pref, upf4, upf6 string
		wantUpf, wantGnb                 string
	}{
		{"IPv4", tGnb4, "", "", tUpf4, "", tUpf4, tGnb4},
		{"IPv6", tGnb6, "", "", "", tUpf6, tUpf6, tGnb6},
		{"160 bits, IPv4 gNB", tGnb4, "", "", tUpf4, tUpf6, tUpf4, tGnb4},
		{"160 bits, IPv6 gNB", tGnb6, "", "", tUpf4, tUpf6, tUpf6, tGnb6},
		{"160 bits, dual gNB", tGnb4, tGnb6, "", tUpf4, tUpf6, tUpf4, tGnb4},
		{"160 bits, dual gNB, prefer IPv6", tGnb4, tGnb6, "ipv6", tUpf4, tUpf6, tUpf6, tGnb6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gnbue := n3TestGnbUe(tc.n3, tc.n3v6, tc.pref)
			dbParam, err := setupPduSession(gnbue, setupItem(t, tc.upf4, tc.upf6))
			if err != nil {
				t.Fatalf("setupPduSession: %v", err)
			}
			if got := dbParam.PduSess.GnbN3Ip; got != tc.wantGnb {
				t.Errorf("gNB N3 address = %q, want %q", got, tc.wantGnb)
			}
			upue, err := gnbue.GetGnbUpUe(1)
			if err != nil || upue.Upf == nil {
				t.Fatalf("no user plane context: %v", err)
			}
			if got := upue.Upf.GetIpAddr(); got != tc.wantUpf {
				t.Errorf("UPF = %q, want %q", got, tc.wantUpf)
			}
		})
	}
}

// A tunnel the gNB has no address for fails the session, and its DL TEID is given back.
func TestSetupPduSessionFailsWithoutAnAddressOfTheFamily(t *testing.T) {
	gnbue := n3TestGnbUe(tGnb4, "", "")
	if _, err := setupPduSession(gnbue, setupItem(t, "", tUpf6)); err == nil {
		t.Fatal("an IPv6 tunnel was set up on an IPv4-only gNB")
	}
	teid, err := gnbue.Gnb.DlTeidGenerator.Allocate()
	if err != nil || teid != 1 {
		t.Errorf("the next DL TEID is %d (%v), want 1: the failed session kept its TEID", teid, err)
	}
}
