// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	profctx "github.com/omec-project/gnbsim/profile/context"
	"github.com/omec-project/nas/v2/nasMessage"
)

func TestNewSimUeRequestsTheProfilesPduSessionType(t *testing.T) {
	profile := &profctx.Profile{NasPduSessionType: nasMessage.PDUSessionTypeIPv4IPv6}
	ue := NewSimUe("imsi-208930100007501", nil, profile, nil)
	if got := ue.RealUe.RequestedPduSessionType(); got != nasMessage.PDUSessionTypeIPv4IPv6 {
		t.Errorf("RequestedPduSessionType = %d, want IPv4v6", got)
	}
	ue = NewSimUe("imsi-208930100007502", nil, &profctx.Profile{}, nil)
	if got := ue.RealUe.RequestedPduSessionType(); got != nasMessage.PDUSessionTypeIPv4 {
		t.Errorf("RequestedPduSessionType without an option = %d, want IPv4", got)
	}
}
