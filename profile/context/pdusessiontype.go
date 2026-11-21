// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"strings"

	"github.com/omec-project/nas/v2/nasMessage"
)

// pduSessionTypes maps the values of the pduSessionType profile option, in lower case, to the PDU
// session type value of TS 24.501 clause 9.11.4.11. Ethernet and Unstructured are there for testing
// how the network refuses them: the UE has no user plane for either.
var pduSessionTypes = map[string]uint8{
	"ipv4":         nasMessage.PDUSessionTypeIPv4,
	"ipv6":         nasMessage.PDUSessionTypeIPv6,
	"ipv4v6":       nasMessage.PDUSessionTypeIPv4IPv6,
	"unstructured": nasMessage.PDUSessionTypeUnstructured,
	"ethernet":     nasMessage.PDUSessionTypeEthernet,
}

// ParsePduSessionType returns the NAS PDU session type value for the pduSessionType profile option:
// IPv4 (the default when empty), IPv6, IPv4v6, Unstructured or Ethernet, in any case.
func ParsePduSessionType(option string) (uint8, error) {
	if option == "" {
		return nasMessage.PDUSessionTypeIPv4, nil
	}
	if value, ok := pduSessionTypes[strings.ToLower(option)]; ok {
		return value, nil
	}
	return 0, fmt.Errorf("pduSessionType %q, want IPv4, IPv6, IPv4v6, Unstructured or Ethernet", option)
}
