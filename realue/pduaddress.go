// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package realue

import (
	"fmt"
	"net"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/nas/v2/nasType"
)

// PDU address IE lengths (TS 24.501 clause 9.11.4.10): the PDU session type octet, then the
// address information of that type.
const (
	pduAddressLenIPv4   = 1 + net.IPv4len // the IPv4 address
	pduAddressLenIPv6   = 1 + 8           // the interface identifier of the IPv6 link-local address
	pduAddressLenIPv4v6 = 1 + 8 + 4       // the interface identifier, then the IPv4 address
)

// decodePduAddress returns the UE's IPv4 address and IPv6 interface identifier from the PDU address
// of a PDU Session Establishment Accept, for the session's selected PDU session type: IPv4 has the
// address, IPv6 the 8-octet interface identifier (the prefix comes in a router advertisement), and
// IPv4v6 both, the identifier first. Other types carry no PDU address and give neither.
func decodePduAddress(sessionType uint8, address *nasType.PDUAddress) (ipv4 net.IP, interfaceID []byte, err error) {
	var wantLen uint8
	switch sessionType {
	case nasMessage.PDUSessionTypeIPv4:
		wantLen = pduAddressLenIPv4
	case nasMessage.PDUSessionTypeIPv6:
		wantLen = pduAddressLenIPv6
	case nasMessage.PDUSessionTypeIPv4IPv6:
		wantLen = pduAddressLenIPv4v6
	default:
		return nil, nil, nil
	}
	if address == nil {
		return nil, nil, fmt.Errorf("no PDU address for PDU session type %d", sessionType)
	}
	if got := address.GetPDUSessionTypeValue(); got != sessionType {
		return nil, nil, fmt.Errorf("the PDU address is of PDU session type %d, the session of %d", got, sessionType)
	}
	if got := address.GetLen(); got < wantLen {
		return nil, nil, fmt.Errorf("PDU address of %d octets, PDU session type %d needs %d", got, sessionType, wantLen)
	}
	info := address.GetPDUAddressInformation()
	switch sessionType {
	case nasMessage.PDUSessionTypeIPv4:
		ipv4 = net.IPv4(info[0], info[1], info[2], info[3])
	case nasMessage.PDUSessionTypeIPv6:
		interfaceID = append([]byte(nil), info[:8]...)
	case nasMessage.PDUSessionTypeIPv4IPv6:
		interfaceID = append([]byte(nil), info[:8]...)
		ipv4 = net.IPv4(info[8], info[9], info[10], info[11])
	}
	return ipv4, interfaceID, nil
}

// formatInterfaceID writes an interface identifier as the low 64 bits of an IPv6 address.
func formatInterfaceID(interfaceID []byte) string {
	if len(interfaceID) != 8 {
		return ""
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip[8:], interfaceID)
	return ip.String()
}
