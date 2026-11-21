// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/omec-project/gnbsim/common"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// the address families a session with IPv6 pings, in this order
const (
	familyIPv4 = "IPv4"
	familyIPv6 = "IPv6"
)

// maxRtrSolicitations is MAX_RTR_SOLICITATIONS of RFC 4861 clause 10: the router solicitations a
// data request sends before it gives up waiting for a router advertisement.
const maxRtrSolicitations = 3

// rtrSolicitationInterval is RTR_SOLICITATION_INTERVAL of RFC 4861 clause 10.
var rtrSolicitationInterval = 4 * time.Second

// allNodesMulticast is ff02::1, the destination of an unsolicited router advertisement.
var allNodesMulticast = net.ParseIP("ff02::1")

// hasIPv6 tells whether the network gave the session IPv6: an IPv6 or IPv4v6 PDU address. A session
// without it keeps the IPv4-only data path.
func hasIPv6(pduSess *realuectx.PduSession) bool {
	return pduSess.Ipv6InterfaceId != nil
}

// pingFamilies are the address families of the session's echo requests.
func pingFamilies(pduSess *realuectx.PduSession) []string {
	if pduSess.PduAddress.To4() != nil {
		return []string{familyIPv4, familyIPv6}
	}
	return []string{familyIPv6}
}

// requestIPv6Data starts a data request on a session with IPv6. The UE solicits a router
// advertisement first (TS 23.501 clause 5.8.2.2.2) and pings once it has formed its address from
// the advertised prefix.
func requestIPv6Data(pduSess *realuectx.PduSession) error {
	if net.ParseIP(pduSess.DefaultAsV6) == nil || net.ParseIP(pduSess.DefaultAsV6).To4() != nil {
		return fmt.Errorf("pdu session %d has IPv6 but no IPv6 destination: %q",
			pduSess.PduSessId, pduSess.DefaultAsV6)
	}
	pduSess.DataPending = true
	pduSess.RsSent = 0
	return sendRouterSolicitation(pduSess)
}

// sendRouterSolicitation sends a router solicitation and arms its retransmission.
func sendRouterSolicitation(pduSess *realuectx.PduSession) error {
	rs := buildRouterSolicitation(linkLocalAddress(pduSess.Ipv6InterfaceId))
	if err := sendUplink(pduSess, rs, nil); err != nil {
		return err
	}
	pduSess.RsSent++
	pduSess.RsTimer = time.NewTimer(rtrSolicitationInterval)
	pduSess.Log.Infof("sent router solicitation %d of %d", pduSess.RsSent, maxRtrSolicitations)
	return nil
}

// rsTimerChan is the retransmission timer of a pending router solicitation, or nil, which a
// select never picks, when there is none.
func rsTimerChan(pduSess *realuectx.PduSession) <-chan time.Time {
	if pduSess.RsTimer == nil {
		return nil
	}
	return pduSess.RsTimer.C
}

// stopRouterSolicitation gives up a data request that waits for a router advertisement.
func stopRouterSolicitation(pduSess *realuectx.PduSession) {
	if pduSess.RsTimer != nil {
		pduSess.RsTimer.Stop()
		pduSess.RsTimer = nil
	}
	pduSess.DataPending = false
}

// HandleRsTimeout is the end of the wait for an answer to a router solicitation. The solicitation
// is sent again up to maxRtrSolicitations times. After that, a prefix that came in an unsolicited
// advertisement is used, and without one the data request fails.
func HandleRsTimeout(pduSess *realuectx.PduSession) error {
	pduSess.RsTimer = nil
	if !pduSess.DataPending {
		return nil
	}
	if pduSess.RsSent < maxRtrSolicitations {
		return sendRouterSolicitation(pduSess)
	}
	if pduSess.Ipv6Address == nil {
		pduSess.DataPending = false
		return fmt.Errorf("no router advertisement after %d router solicitations", pduSess.RsSent)
	}
	pduSess.Log.Warnf("no answer to %d router solicitations, using %v from an earlier router advertisement",
		pduSess.RsSent, pduSess.Ipv6Address)
	pduSess.DataPending = false
	return startIPv6Data(pduSess)
}

// handleIPv6Packet handles a downlink IPv6 packet: router advertisements and echo replies. Other
// neighbour discovery and MLD messages are ignored, the rest is an error.
func handleIPv6Packet(pduSess *realuectx.PduSession, pkt []byte) error {
	m, err := parseICMPv6(pkt)
	if err != nil {
		return err
	}
	switch m.icmpType() {
	case ipv6.ICMPTypeRouterAdvertisement:
		return handleRouterAdvertisement(pduSess, m)
	case ipv6.ICMPTypeEchoReply:
		if !m.dst.Equal(pduSess.Ipv6Address) {
			return fmt.Errorf("ICMPv6 echo reply to %v, the UE's address is %v", m.dst, pduSess.Ipv6Address)
		}
		msg, err := icmp.ParseMessage(protoICMPv6, m.msg)
		if err != nil {
			return fmt.Errorf("failed to parse icmpv6 message:%v", err)
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			return errors.New("icmpv6 echo reply without an echo body")
		}
		pduSess.Log.Infof("received ICMPv6 Echo Reply, ID:%v, Seq:%v", echo.ID, echo.Seq)
		pduSess.RxDataPktCount++
		return echoReplied(pduSess, familyIPv6)
	case ipv6.ICMPTypeMulticastListenerQuery, ipv6.ICMPTypeMulticastListenerReport,
		ipv6.ICMPTypeMulticastListenerDone, ipv6.ICMPTypeRouterSolicitation,
		ipv6.ICMPTypeNeighborSolicitation, ipv6.ICMPTypeNeighborAdvertisement,
		ipv6.ICMPTypeRedirect, ipv6.ICMPTypeVersion2MulticastListenerReport:
		pduSess.Log.Debugf("ignoring ICMPv6 %v from %v", m.icmpType(), m.src)
		return nil
	default:
		return fmt.Errorf("unsupported icmpv6 message type:%v", m.icmpType())
	}
}

// handleRouterAdvertisement forms the UE's address from the advertised prefix and starts a data
// request that waits for it.
func handleRouterAdvertisement(pduSess *realuectx.PduSession, m *icmpv6Message) error {
	prefix, err := parseRouterAdvertisement(m)
	if errors.Is(err, errNoUsablePrefix) {
		pduSess.Log.Warnf("router advertisement from %v without a prefix to autoconfigure from", m.src)
		return nil
	}
	if err != nil {
		return err
	}
	solicited := m.dst.Equal(linkLocalAddress(pduSess.Ipv6InterfaceId))
	if !solicited && !m.dst.Equal(allNodesMulticast) {
		return fmt.Errorf("router advertisement to %v, neither the UE nor all nodes", m.dst)
	}
	pduSess.RaReceived++
	if solicited {
		pduSess.RaSolicited++
	}
	address := slaacAddress(prefix, pduSess.Ipv6InterfaceId)
	if !address.Equal(pduSess.Ipv6Address) {
		pduSess.Log.Infof("IPv6 prefix %v/%d from %v, UE address %v", prefix, slaacPrefixLen, m.src, address)
	}
	pduSess.Ipv6Prefix = prefix
	pduSess.Ipv6Address = address
	if !pduSess.DataPending {
		return nil
	}
	stopRouterSolicitation(pduSess)
	return startIPv6Data(pduSess)
}

// startIPv6Data pings once the UE has its IPv6 address. One-off echo requests (no interval) go one
// address family after the other, each the requested number of times, the next sent on the reply
// to the last. With an interval, each tick sends one echo request of each family.
func startIPv6Data(pduSess *realuectx.PduSession) error {
	families := pingFamilies(pduSess)
	if pduSess.ReqDataPktInt == 0 {
		pduSess.PingFamilies = families
		pduSess.PingPhase = 0
		pduSess.PhaseTxCount = 0
		return sendEcho(pduSess, families[0], nil)
	}
	// the generator gets its own copy of what the event loop may change meanwhile
	src, dst := append(net.IP(nil), pduSess.Ipv6Address...), net.ParseIP(pduSess.DefaultAsV6)
	count, interval := pduSess.ReqDataPktCount, time.Duration(pduSess.ReqDataPktInt)*time.Second
	stop := make(chan struct{})
	pduSess.GenStop = stop
	pduSess.GenWg.Go(func() {
		for tick := 0; tick < count; tick++ {
			for _, family := range families {
				var err error
				if family == familyIPv4 {
					err = sendIcmpEchoRequest(pduSess, stop)
				} else {
					err = sendIcmpv6EchoRequest(pduSess, src, dst, stop)
				}
				if err != nil {
					pduSess.Log.Errorf("failed to send %s echo req: %v", family, err)
					return
				}
			}
			select {
			case <-time.After(interval):
			case <-stop:
				return
			}
		}
		msg := &common.UuMessage{}
		msg.Event = common.DATA_PKT_GEN_SUCCESS_EVENT
		select {
		case pduSess.WriteUeChan <- msg:
			pduSess.Log.Debugln("sent Data Packet Generation Success Event")
		case <-stop:
		}
	})
	return nil
}

// sendEcho sends one echo request of the family, from the event loop.
func sendEcho(pduSess *realuectx.PduSession, family string, stop <-chan struct{}) error {
	pduSess.PhaseTxCount++
	if family == familyIPv4 {
		return sendIcmpEchoRequest(pduSess, stop)
	}
	return sendIcmpv6EchoRequest(pduSess, pduSess.Ipv6Address, net.ParseIP(pduSess.DefaultAsV6), stop)
}

// echoReplied moves the one-off echo requests of a session with IPv6 on, after a reply of family.
func echoReplied(pduSess *realuectx.PduSession, family string) error {
	// a generator sends regardless of the replies, and a late reply is not the current family's
	if pduSess.ReqDataPktInt != 0 || pduSess.PingPhase >= len(pduSess.PingFamilies) ||
		pduSess.PingFamilies[pduSess.PingPhase] != family {
		return nil
	}
	if pduSess.PhaseTxCount < pduSess.ReqDataPktCount {
		return sendEcho(pduSess, family, nil)
	}
	pduSess.PingPhase++
	pduSess.PhaseTxCount = 0
	if pduSess.PingPhase < len(pduSess.PingFamilies) {
		return sendEcho(pduSess, pduSess.PingFamilies[pduSess.PingPhase], nil)
	}
	pduSess.PingFamilies = nil
	msg := &common.UuMessage{}
	msg.Event = common.DATA_PKT_GEN_SUCCESS_EVENT
	pduSess.WriteUeChan <- msg
	pduSess.Log.Debugln("sent Data Packet Generation Success Event")
	return nil
}

// sendIcmpv6EchoRequest sends an ICMPv6 echo request with the payload of the IPv4 one.
func sendIcmpv6EchoRequest(pduSess *realuectx.PduSession, src, dst net.IP, stop <-chan struct{}) error {
	data, err := hex.DecodeString(echoPayload)
	if err != nil {
		return err
	}
	pkt, err := buildIcmpv6EchoRequest(src, dst, pduSess.GetNextSeqNum(), data)
	if err != nil {
		return fmt.Errorf("failed to marshal icmpv6 message: %v", err)
	}
	if err := sendUplink(pduSess, pkt, stop); err != nil {
		return err
	}
	pduSess.TxDataPktCount++
	pduSess.Log.Debugln("sent UL ICMPv6 ping message")
	return nil
}
