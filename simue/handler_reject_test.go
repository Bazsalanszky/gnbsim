// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package simue

import (
	"testing"

	"github.com/omec-project/gnbsim/common"
	profctx "github.com/omec-project/gnbsim/profile/context"
	simuectx "github.com/omec-project/gnbsim/simue/context"
	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v4"
)

// 5GSM causes of TS 24.501 table 9.11.4.2.1
const (
	causeIPv4Only = 50
	causeIPv6Only = 51
)

func pduSessEstUe(rejectCause uint8) (*simuectx.SimUe, chan *common.ProfileMessage) {
	results := make(chan *common.ProfileMessage, 1)
	return &simuectx.SimUe{
		Supi:             testSupi,
		Procedure:        common.PDU_SESSION_ESTABLISHMENT_PROCEDURE,
		WriteProfileChan: results,
		WriteRealUeChan:  make(chan common.InterfaceMessage, 1),
		Log:              zap.NewNop().Sugar(),
		ProfileCtx:       &profctx.Profile{PduSessionRejectCause: rejectCause},
	}, results
}

func pduSessEstReject(cause uint8) *common.UeMessage {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.PDUSessionEstablishmentReject = nasMessage.NewPDUSessionEstablishmentReject(0)
	m.PDUSessionEstablishmentReject.SetCauseValue(cause)
	msg := &common.UeMessage{NasMsg: m}
	msg.Event = common.PDU_SESS_EST_REJECT_EVENT
	return msg
}

// A profile that expects the reject passes the procedure on that cause, and only on that one.
func TestExpectedPduSessionReject(t *testing.T) {
	ue, results := pduSessEstUe(causeIPv6Only)
	if err := HandlePduSessEstRejectEvent(ue, pduSessEstReject(causeIPv6Only)); err != nil {
		t.Fatalf("the expected reject failed the procedure: %v", err)
	}
	select {
	case got := <-results:
		if got.Event != common.PROC_PASS_EVENT || got.Proc != common.PDU_SESSION_ESTABLISHMENT_PROCEDURE {
			t.Errorf("profile was told %v for %v", got.Event, got.Proc)
		}
	default:
		t.Fatal("the procedure did not pass")
	}

	ue, results = pduSessEstUe(causeIPv6Only)
	if err := HandlePduSessEstRejectEvent(ue, pduSessEstReject(causeIPv4Only)); err == nil {
		t.Error("a reject with another cause passed")
	}
	if len(results) != 0 {
		t.Error("a reject with another cause reported a result")
	}

	accept := &common.UeMessage{}
	accept.Event = common.PDU_SESS_EST_ACCEPT_EVENT
	ue, _ = pduSessEstUe(causeIPv6Only)
	if err := HandlePduSessEstAcceptEvent(ue, accept); err == nil {
		t.Error("an accept passed where a reject was expected")
	}
}

// Without the option a reject fails the procedure, as before; one without its NAS message, too.
func TestUnexpectedPduSessionReject(t *testing.T) {
	ue, results := pduSessEstUe(0)
	if err := HandlePduSessEstRejectEvent(ue, pduSessEstReject(causeIPv4Only)); err == nil {
		t.Error("a reject passed a profile that expects an accept")
	}
	bare := &common.UeMessage{}
	bare.Event = common.PDU_SESS_EST_REJECT_EVENT
	if err := HandlePduSessEstRejectEvent(ue, bare); err == nil {
		t.Error("a reject without its NAS message was taken")
	}
	if len(results) != 0 {
		t.Error("a result was reported")
	}
}

func TestProfileReadsPduSessionRejectCause(t *testing.T) {
	p := &profctx.Profile{}
	if err := yaml.Unmarshal([]byte("pduSessionRejectCause: 51\n"), p); err != nil {
		t.Fatal(err)
	}
	if p.PduSessionRejectCause != causeIPv6Only {
		t.Errorf("pduSessionRejectCause read as %d", p.PduSessionRejectCause)
	}
}
