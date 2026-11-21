// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/omec-project/gnbsim/common"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"go.uber.org/zap"
	"golang.org/x/net/ipv6"
)

// testIPv4Echo is the IPv4 echo request a session from testUeAddr to testDefaultAs sends first, as
// gNBSim has always sent it.
const testIPv4Echo = "4500004c000100004001b6050a000001c0a8fa0108006f3a306a0001" + echoPayload

// newTestSession is a session connected to a gNB, with IPv4 when v4 and IPv6 when v6.
func newTestSession(v4, v6 bool) (pduSess *realuectx.PduSession, gnb, ue chan common.InterfaceMessage) {
	gnb = make(chan common.InterfaceMessage, 16)
	ue = make(chan common.InterfaceMessage, 16)
	pduSess = &realuectx.PduSession{
		WriteGnbChan: gnb, WriteUeChan: ue,
		ReadDlChan:  make(chan common.InterfaceMessage, 16),
		ReadCmdChan: make(chan common.InterfaceMessage, 16),
		Log:         zap.NewNop().Sugar(),
	}
	if v4 {
		pduSess.PduAddress = net.ParseIP(testUeAddr).To4()
	}
	if v6 {
		pduSess.Ipv6InterfaceId = testIID
	}
	return pduSess, gnb, ue
}

func dataRequest(count, interval int) *common.UeMessage {
	msg := &common.UeMessage{}
	msg.Event = common.DATA_PKT_GEN_REQUEST_EVENT
	msg.UserDataPktCount, msg.UserDataPktInterval = count, interval
	msg.DefaultAs, msg.DefaultAsV6 = testDefaultAs, testDefaultAs6
	return msg
}

func downlink(t *testing.T, pduSess *realuectx.PduSession, pkt []byte) {
	t.Helper()
	msg := &common.UserDataMessage{}
	msg.Event = common.DL_UE_DATA_TRANSFER_EVENT
	msg.Payload = pkt
	if err := HandleDlMessage(pduSess, msg); err != nil {
		t.Fatalf("downlink packet refused: %v", err)
	}
}

func uplink(t *testing.T, gnb chan common.InterfaceMessage) []byte {
	t.Helper()
	select {
	case msg := <-gnb:
		return msg.(*common.UserDataMessage).Payload
	case <-time.After(3 * time.Second):
		t.Fatal("no uplink packet")
		return nil
	}
}

func noUplink(t *testing.T, gnb chan common.InterfaceMessage) {
	t.Helper()
	if len(gnb) != 0 {
		t.Fatalf("unexpected uplink packet %x", (<-gnb).(*common.UserDataMessage).Payload)
	}
}

// echoReply is the answer of the data network to an echo request of either family.
func echoReply(t *testing.T, req []byte) []byte {
	t.Helper()
	rep := append([]byte(nil), req...)
	if req[0]>>4 == 4 {
		copy(rep[12:16], req[16:20])
		copy(rep[16:20], req[12:16])
		rep[20] = 0 // echo reply
		return rep
	}
	m, err := parseICMPv6(req)
	if err != nil || m.icmpType() != ipv6.ICMPTypeEchoRequest {
		t.Fatalf("not an ICMPv6 echo request: %v", err)
	}
	msg := append([]byte(nil), m.msg...)
	msg[0], msg[2], msg[3] = byte(ipv6.ICMPTypeEchoReply), 0, 0
	binary.BigEndian.PutUint16(msg[2:4], icmpv6Checksum(m.dst, m.src, msg))
	return ipv6Packet(m.dst, m.src, 64, msg)
}

func wantRS(t *testing.T, pkt []byte) {
	t.Helper()
	if got, want := hex.EncodeToString(pkt), hex.EncodeToString(buildRouterSolicitation(linkLocalAddress(testIID))); got != want {
		t.Fatalf("uplink %s, want a router solicitation", got)
	}
}

func wantEcho6(t *testing.T, pkt []byte) {
	t.Helper()
	m, err := parseICMPv6(pkt)
	if err != nil || m.icmpType() != ipv6.ICMPTypeEchoRequest || !m.src.Equal(testUeAddr6) ||
		!m.dst.Equal(net.ParseIP(testDefaultAs6)) {
		t.Fatalf("uplink %x, want an ICMPv6 echo request from %v: %v", pkt, testUeAddr6, err)
	}
}

func wantSuccess(t *testing.T, ue chan common.InterfaceMessage) {
	t.Helper()
	select {
	case msg := <-ue:
		if msg.GetEventType() != common.DATA_PKT_GEN_SUCCESS_EVENT {
			t.Fatalf("the UE was sent %v", msg.GetEventType())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the data request did not succeed")
	}
}

// An IPv4 session sends what it always sent, and an IPv6 packet has no business on it.
func TestIPv4SessionIsUnchanged(t *testing.T) {
	pduSess, gnb, ue := newTestSession(true, false)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(2, 0)); err != nil {
		t.Fatal(err)
	}
	req := uplink(t, gnb)
	if got := hex.EncodeToString(req); got != testIPv4Echo {
		t.Fatalf("IPv4 echo request\n got %s\nwant %s", got, testIPv4Echo)
	}
	downlink(t, pduSess, echoReply(t, req))
	uplink(t, gnb)
	downlink(t, pduSess, echoReply(t, req))
	wantSuccess(t, ue)
	noUplink(t, gnb)

	msg := &common.UserDataMessage{}
	msg.Payload = usableRA(allNodesMulticast)
	if err := HandleDlMessage(pduSess, msg); err == nil {
		t.Error("an IPv6 packet was taken on a session without IPv6")
	}
}

// An IPv6 session solicits a router advertisement, forms its address from the prefix and pings
// the IPv6 destination, the next echo request on each reply.
func TestIPv6SessionSolicitsThenPings(t *testing.T) {
	pduSess, gnb, ue := newTestSession(false, true)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(2, 0)); err != nil {
		t.Fatal(err)
	}
	wantRS(t, uplink(t, gnb))
	noUplink(t, gnb)
	if pduSess.RsTimer == nil || !pduSess.DataPending {
		t.Fatal("no retransmission is armed")
	}

	downlink(t, pduSess, usableRA(linkLocalAddress(testIID)))
	if !pduSess.Ipv6Address.Equal(testUeAddr6) || !pduSess.Ipv6Prefix.Equal(testPrefix) {
		t.Fatalf("address %v, prefix %v", pduSess.Ipv6Address, pduSess.Ipv6Prefix)
	}
	if pduSess.RsTimer != nil || pduSess.DataPending || pduSess.RaSolicited != 1 {
		t.Errorf("timer %v, pending %v, solicited %d", pduSess.RsTimer, pduSess.DataPending, pduSess.RaSolicited)
	}
	req := uplink(t, gnb)
	wantEcho6(t, req)
	downlink(t, pduSess, echoReply(t, req))
	req = uplink(t, gnb)
	wantEcho6(t, req)
	downlink(t, pduSess, echoReply(t, req))
	wantSuccess(t, ue)
	noUplink(t, gnb)
	if pduSess.TxDataPktCount != 2 || pduSess.RxDataPktCount != 2 {
		t.Errorf("sent %d, received %d", pduSess.TxDataPktCount, pduSess.RxDataPktCount)
	}

	// a later advertisement neither pings nor fails
	downlink(t, pduSess, usableRA(allNodesMulticast))
	noUplink(t, gnb)
	if pduSess.RaReceived != 2 || pduSess.RaSolicited != 1 {
		t.Errorf("received %d, solicited %d", pduSess.RaReceived, pduSess.RaSolicited)
	}
}

// An IPv4v6 session pings IPv4 first, with the packets of an IPv4 session, then IPv6.
func TestIPv4v6SessionPingsBothFamilies(t *testing.T) {
	pduSess, gnb, ue := newTestSession(true, true)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(1, 0)); err != nil {
		t.Fatal(err)
	}
	wantRS(t, uplink(t, gnb))
	downlink(t, pduSess, usableRA(linkLocalAddress(testIID)))
	req := uplink(t, gnb)
	if got := hex.EncodeToString(req); got != testIPv4Echo {
		t.Fatalf("IPv4 echo request\n got %s\nwant %s", got, testIPv4Echo)
	}
	// a reply of the other family than the one being pinged moves nothing on
	downlink(t, pduSess, echoReply(t, mustEcho6(t)))
	noUplink(t, gnb)
	downlink(t, pduSess, echoReply(t, req))
	req = uplink(t, gnb)
	wantEcho6(t, req)
	downlink(t, pduSess, echoReply(t, req))
	wantSuccess(t, ue)
	noUplink(t, gnb)
}

func mustEcho6(t *testing.T) []byte {
	t.Helper()
	pkt, err := buildIcmpv6EchoRequest(testUeAddr6, net.ParseIP(testDefaultAs6), 99, echoData(t))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

// With an interval, each tick sends an echo request of each family, whatever comes back.
func TestIPv4v6SessionGeneratorSendsBothFamiliesPerTick(t *testing.T) {
	pduSess, gnb, ue := newTestSession(true, true)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(1, 1)); err != nil {
		t.Fatal(err)
	}
	wantRS(t, uplink(t, gnb))
	downlink(t, pduSess, usableRA(linkLocalAddress(testIID)))
	if got := hex.EncodeToString(uplink(t, gnb)); got != testIPv4Echo {
		t.Fatalf("IPv4 echo request %s", got)
	}
	wantEcho6(t, uplink(t, gnb))
	wantSuccess(t, ue)
	stopGenerator(pduSess)
	noUplink(t, gnb)
}

// An advertisement that came before the data request gives the address, but the request still
// solicits one, to see the network answer.
func TestUnsolicitedAdvertisementIsRemembered(t *testing.T) {
	pduSess, gnb, _ := newTestSession(false, true)
	downlink(t, pduSess, usableRA(allNodesMulticast))
	if !pduSess.Ipv6Address.Equal(testUeAddr6) || pduSess.RaReceived != 1 || pduSess.RaSolicited != 0 {
		t.Fatalf("address %v, received %d, solicited %d", pduSess.Ipv6Address, pduSess.RaReceived, pduSess.RaSolicited)
	}
	noUplink(t, gnb)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(1, 0)); err != nil {
		t.Fatal(err)
	}
	wantRS(t, uplink(t, gnb))
	noUplink(t, gnb)
}

// Unanswered solicitations are sent again, up to three; then the request falls back on an earlier
// advertisement, or fails without one.
func TestRouterSolicitationRetransmission(t *testing.T) {
	pduSess, gnb, _ := newTestSession(false, true)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(1, 0)); err != nil {
		t.Fatal(err)
	}
	wantRS(t, uplink(t, gnb))
	for i := 2; i <= maxRtrSolicitations; i++ {
		if err := HandleRsTimeout(pduSess); err != nil {
			t.Fatal(err)
		}
		wantRS(t, uplink(t, gnb))
	}
	if err := HandleRsTimeout(pduSess); err == nil {
		t.Fatal("no advertisement after three solicitations and no failure")
	}
	noUplink(t, gnb)
	if pduSess.DataPending || pduSess.RsSent != maxRtrSolicitations {
		t.Errorf("pending %v, sent %d", pduSess.DataPending, pduSess.RsSent)
	}

	// the same with the address of an unsolicited advertisement to fall back on
	pduSess, gnb, _ = newTestSession(false, true)
	downlink(t, pduSess, usableRA(allNodesMulticast))
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(1, 0)); err != nil {
		t.Fatal(err)
	}
	uplink(t, gnb)
	for range maxRtrSolicitations - 1 {
		if err := HandleRsTimeout(pduSess); err != nil {
			t.Fatal(err)
		}
		uplink(t, gnb)
	}
	if err := HandleRsTimeout(pduSess); err != nil {
		t.Fatal(err)
	}
	wantEcho6(t, uplink(t, gnb))

	// a timer left over from a request that has been given up does nothing
	pduSess.DataPending = false
	if err := HandleRsTimeout(pduSess); err != nil {
		t.Fatal(err)
	}
	noUplink(t, gnb)
}

// The retransmission runs on the session's event loop, and the failure reaches the UE.
func TestEventLoopRetransmitsSolicitations(t *testing.T) {
	old := rtrSolicitationInterval
	rtrSolicitationInterval = 20 * time.Millisecond
	oldWait := lastPktWaitTimeout
	lastPktWaitTimeout = 100 * time.Millisecond
	defer func() { rtrSolicitationInterval, lastPktWaitTimeout = old, oldWait }()

	pduSess, gnb, ue := newTestSession(false, true)
	done := make(chan struct{})
	go func() { HandleEvents(pduSess); close(done) }()
	pduSess.ReadCmdChan <- dataRequest(1, 0)
	for range maxRtrSolicitations {
		wantRS(t, uplink(t, gnb))
	}
	select {
	case msg := <-ue:
		if msg.GetEventType() != common.ERROR_EVENT {
			t.Fatalf("the UE was sent %v", msg.GetEventType())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the unanswered solicitations were not reported")
	}
	noUplink(t, gnb)
	quit := &common.UeMessage{}
	quit.Event = common.QUIT_EVENT
	pduSess.ReadCmdChan <- quit
	go func() {
		for range gnb { // the quit hands the gNB its marker
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the event loop did not quit")
	}
}

// A release gives up the wait for an advertisement.
func TestReleaseStopsTheSolicitation(t *testing.T) {
	pduSess, gnb, _ := newTestSession(false, true)
	if err := HandleDataPktGenRequestEvent(pduSess, dataRequest(1, 0)); err != nil {
		t.Fatal(err)
	}
	uplink(t, gnb)
	if err := HandleConnectionReleaseRequestEvent(pduSess, &common.UeMessage{}); err != nil {
		t.Fatal(err)
	}
	if pduSess.RsTimer != nil || pduSess.DataPending {
		t.Error("the solicitation was not stopped")
	}
	downlink(t, pduSess, usableRA(linkLocalAddress(testIID)))
	if pduSess.Ipv6Address == nil {
		t.Error("the advertisement was not taken")
	}
}

func TestIPv6DownlinkRefusals(t *testing.T) {
	pduSess, _, _ := newTestSession(false, true)
	pduSess.Ipv6Address = testUeAddr6
	ns := make([]byte, 24)
	ns[0] = byte(ipv6.ICMPTypeNeighborSolicitation)
	binary.BigEndian.PutUint16(ns[2:4], icmpv6Checksum(testRouterLL, testUeAddr6, ns))
	downlink(t, pduSess, ipv6Packet(testRouterLL, testUeAddr6, 255, ns)) // ignored

	unreachable := make([]byte, 8)
	unreachable[0] = byte(ipv6.ICMPTypeDestinationUnreachable)
	binary.BigEndian.PutUint16(unreachable[2:4], icmpv6Checksum(testRouterLL, testUeAddr6, unreachable))
	// a valid reply, but to another interface identifier
	otherReq, err := buildIcmpv6EchoRequest(net.ParseIP("2a0e:8f02:f07b:500::1"), net.ParseIP(testDefaultAs6), 1, echoData(t))
	if err != nil {
		t.Fatal(err)
	}
	otherUe := echoReply(t, otherReq)
	for name, pkt := range map[string][]byte{
		"destination unreachable":  ipv6Packet(testRouterLL, testUeAddr6, 64, unreachable),
		"reply to another address": otherUe,
		"RA to someone else": routerAdvertisement(testRouterLL, net.ParseIP("fe80::2"), 255, 0,
			prefixInfo(testPrefix, 64, prefixFlagAutoconf, 1)),
	} {
		msg := &common.UserDataMessage{}
		msg.Payload = pkt
		if err := HandleDlMessage(pduSess, msg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// an IPv6 session needs an IPv6 destination to ping
	pduSess, _, _ = newTestSession(false, true)
	req := dataRequest(1, 0)
	req.DefaultAsV6 = testDefaultAs
	if err := HandleDataPktGenRequestEvent(pduSess, req); err == nil {
		t.Error("an IPv4 destination was taken for the IPv6 echo requests")
	}
}
