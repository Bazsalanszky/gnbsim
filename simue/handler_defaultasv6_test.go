// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package simue

import (
	"testing"

	"github.com/omec-project/gnbsim/common"
	profctx "github.com/omec-project/gnbsim/profile/context"
	simuectx "github.com/omec-project/gnbsim/simue/context"
	"go.uber.org/zap"
)

// The data request carries the profile's destinations of both families to the PDU session.
func TestUserDataRequestCarriesBothDestinations(t *testing.T) {
	realUeChan := make(chan common.InterfaceMessage, 1)
	ue := &simuectx.SimUe{
		Supi:            testSupi,
		Log:             zap.NewNop().Sugar(),
		WriteRealUeChan: realUeChan,
		Procedure:       common.USER_DATA_PKT_GENERATION_PROCEDURE,
		ProfileCtx: &profctx.Profile{
			DataPktCount: 3, DefaultAs: "192.168.250.1", DefaultAsV6: "2001:db8::6",
		},
	}
	HandleProcedure(ue) // waits 3 seconds before it sends
	msg := (<-realUeChan).(*common.UeMessage)
	if msg.Event != common.DATA_PKT_GEN_REQUEST_EVENT || msg.UserDataPktCount != 3 ||
		msg.DefaultAs != "192.168.250.1" || msg.DefaultAsV6 != "2001:db8::6" {
		t.Errorf("data request %v: count %d, destinations %q and %q",
			msg.Event, msg.UserDataPktCount, msg.DefaultAs, msg.DefaultAsV6)
	}
}
