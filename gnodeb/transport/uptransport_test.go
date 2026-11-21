// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/omec-project/gnbsim/common"
	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
)

// fakeUpf is a UDP socket that plays a UPF's N3 endpoint.
type fakeUpf struct {
	conn *net.UDPConn
	upf  *gnbctx.GnbUpf
}

func listenOrSkip(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skipf("no %s on this host: %v", ip, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// newFakeUpf registers a UPF with the gNB, as a PDU session setup does, at a test port.
func newFakeUpf(t *testing.T, gnb *gnbctx.GNodeB, ip string) *fakeUpf {
	t.Helper()
	conn := listenOrSkip(t, ip)
	upf, _ := gnb.GnbPeers.GetOrAddGnbUpf(ip)
	upf.UpfAddr.Port = conn.LocalAddr().(*net.UDPAddr).Port
	return &fakeUpf{conn: conn, upf: upf}
}

func newTestGnb(t *testing.T, n3, n3v6 string) (*gnbctx.GNodeB, *GnbUpTransport) {
	t.Helper()
	listenOrSkip(t, "::1").Close()
	gnb := &gnbctx.GNodeB{GnbName: "gnb1", GnbN3Ip: n3, GnbN3Ipv6: n3v6, GnbPeers: gnbctx.NewGnbPeerDao()}
	tr := NewGnbUpTransport(gnb)
	if err := tr.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() {
		tr.Conn.Close()
		if tr.Conn6 != nil {
			tr.Conn6.Close()
		}
	})
	return gnb, tr
}

// exchange sends a packet to the UPF and checks it came from want, then answers it and checks the
// answer reached the UPF's worker.
func exchange(t *testing.T, tr *GnbUpTransport, upf *fakeUpf, want *net.UDPConn) {
	t.Helper()
	pkt := []byte{0x34, 0xff, 0x00, 0x04, 1, 2, 3, 4}
	if err := tr.SendToPeer(upf.upf, pkt, 0); err != nil {
		t.Fatalf("SendToPeer: %v", err)
	}
	buf := make([]byte, 64)
	if err := upf.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := upf.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the UPF got nothing: %v", err)
	}
	if !bytes.Equal(buf[:n], pkt) {
		t.Errorf("the UPF got %x, want %x", buf[:n], pkt)
	}
	if from.String() != want.LocalAddr().String() {
		t.Errorf("sent from %v, want the socket on %v", from, want.LocalAddr())
	}

	reply := []byte{0x34, 0xff, 0x00, 0x04, 5, 6, 7, 8}
	if _, err := upf.conn.WriteToUDP(reply, from); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-upf.upf.ReadChan:
		if got := msg.(*common.TransportMessage).RawPkt; !bytes.Equal(got, reply) {
			t.Errorf("the UPF worker got %x, want %x", got, reply)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the reply did not reach the UPF worker")
	}
}

func TestUpTransportDualStack(t *testing.T) {
	gnb, tr := newTestGnb(t, "127.0.0.1", "::1")
	if tr.Conn6 == nil {
		t.Fatal("no IPv6 socket for n3Ipv6Addr")
	}
	exchange(t, tr, newFakeUpf(t, gnb, "::1"), tr.Conn6)
	exchange(t, tr, newFakeUpf(t, gnb, "127.0.0.1"), tr.Conn)
}

func TestUpTransportIPv6Only(t *testing.T) {
	gnb, tr := newTestGnb(t, "::1", "")
	if tr.Conn6 != nil {
		t.Error("a second socket for an IPv6 n3IpAddr")
	}
	exchange(t, tr, newFakeUpf(t, gnb, "::1"), tr.Conn)
}

func TestUpTransportIPv4OnlyIsOneSocket(t *testing.T) {
	gnb, tr := newTestGnb(t, "127.0.0.1", "")
	if tr.Conn6 != nil {
		t.Error("an IPv6 socket without n3Ipv6Addr")
	}
	exchange(t, tr, newFakeUpf(t, gnb, "127.0.0.1"), tr.Conn)
}
