// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"testing"

	"github.com/omec-project/gnbsim/common"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"go.uber.org/zap"
)

// An IPv6-only session has an interface identifier and no IPv4 address: the IPv4 echo request
// must not go out from 0.0.0.0.
func TestSendIcmpEchoRequestNeedsAnIPv4Address(t *testing.T) {
	toGnb := make(chan common.InterfaceMessage, 1)
	pduSess := &realuectx.PduSession{
		WriteGnbChan:    toGnb,
		Ipv6InterfaceId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		DefaultAs:       testDefaultAs,
		Log:             zap.NewNop().Sugar(),
	}
	if err := SendIcmpEchoRequest(pduSess); err == nil {
		t.Error("an IPv4 echo request was sent for a session without an IPv4 address")
	}
	if len(toGnb) != 0 {
		t.Error("a packet reached the gNB")
	}
}
