// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/omec-project/gnbsim/common"
	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
	"github.com/omec-project/gnbsim/logger"
	"github.com/omec-project/gnbsim/transportcommon"
	"go.uber.org/zap"
)

// Need to check if NGAP may exceed this limit
var MAX_UDP_PKT_LEN int = 65507

// TODO: Should have a context variable which when cancelled will result in
// the termination of the ReceiveFromPeer handler

// GnbUpTransport represents the User Plane transport of the GNodeB
type GnbUpTransport struct {
	GnbInstance *gnbctx.GNodeB

	/* UDP Connection without any association with peers, on n3IpAddr */
	Conn *net.UDPConn

	/* A second UDP connection on n3Ipv6Addr, for a dual-stack N3; nil without one */
	Conn6 *net.UDPConn

	Log *zap.SugaredLogger
}

func NewGnbUpTransport(gnb *gnbctx.GNodeB) *GnbUpTransport {
	transport := &GnbUpTransport{}
	transport.GnbInstance = gnb
	transport.Log = logger.GNodeBLog.With("subcategory", "UserPlaneTransport")

	return transport
}

func (upTprt *GnbUpTransport) Init() error {
	gnb := upTprt.GnbInstance
	var err error
	upTprt.Conn, err = upTprt.listen(gnb.GnbN3Ip)
	if err != nil {
		return err
	}
	if _, ipv6 := gnb.N3Addresses(); ipv6 != "" && ipv6 != gnb.GnbN3Ip {
		upTprt.Conn6, err = upTprt.listen(ipv6)
		if err != nil {
			upTprt.Conn.Close()
			return err
		}
	}
	return nil
}

// listen opens the UDP socket for one N3 address and starts its receiver.
func (upTprt *GnbUpTransport) listen(ip string) (*net.UDPConn, error) {
	ipPort := net.JoinHostPort(ip, strconv.Itoa(upTprt.GnbInstance.GnbN3Port))
	addr, err := net.ResolveUDPAddr("udp", ipPort)
	if err != nil {
		upTprt.Log.Errorln("ResolveUDPAddr returned:", err)
		return nil, fmt.Errorf("invalid ip or port: %v", ipPort)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		upTprt.Log.Errorln("ListenUDP returned:", err)
		return nil, fmt.Errorf("failed to create udp socket: %v", ipPort)
	}

	go upTprt.receiveFrom(conn)

	upTprt.Log.Infoln("User Plane transport listening on:", ipPort)
	return conn, nil
}

// connFor returns the socket to send to a UPF from: the IPv6 one for an IPv6 UPF when n3Ipv6Addr
// is set, else the one on n3IpAddr.
func (upTprt *GnbUpTransport) connFor(upf *net.UDPAddr) *net.UDPConn {
	if upTprt.Conn6 != nil && upf.IP.To4() == nil {
		return upTprt.Conn6
	}
	return upTprt.Conn
}

// SendToPeer sends a GTP-U encoded packet to the specified UPF over the socket
func (upTprt *GnbUpTransport) SendToPeer(peer transportcommon.TransportPeer,
	pkt []byte, id uint64,
) (err error) {
	err = upTprt.CheckTransportParam(peer, pkt)
	if err != nil {
		return err
	}

	upf := peer.(*gnbctx.GnbUpf)

	pktLen := len(pkt)
	n, err := upTprt.connFor(upf.UpfAddr).WriteTo(pkt, upf.UpfAddr)
	if err != nil {
		upTprt.Log.Errorln("WriteTo returned:", err)
		return fmt.Errorf("failed to write on socket")
	} else if n != pktLen {
		return fmt.Errorf("total bytes:%v, written bytes:%v", pktLen, n)
	} else {
		upTprt.Log.Infof("sent UDP Packet, length: %v bytes", n)
	}

	return
}

// ReceiveFromPeer continuously waits for an incoming message from the UPF
// It then routes the message to the GnbUpfWorker
// readErrorBackoff is how long the receive loop waits after a read error before trying again.
const readErrorBackoff = 10 * time.Millisecond

func (upTprt *GnbUpTransport) ReceiveFromPeer(peer transportcommon.TransportPeer) {
	upTprt.receiveFrom(upTprt.Conn)
}

// receiveFrom is ReceiveFromPeer for one of the gNB's N3 sockets.
func (upTprt *GnbUpTransport) receiveFrom(conn *net.UDPConn) {
	for {
		recvMsg := make([]byte, MAX_UDP_PKT_LEN)
		// TODO Handle notification, info
		n, srcAddr, err := conn.ReadFromUDP(recvMsg)
		if err != nil {
			upTprt.Log.Errorln("ReadFromUDP returned:", err)
			if errors.Is(err, net.ErrClosed) {
				// the socket is gone, nothing more can be received
				return
			}
			// a persistent error would otherwise spin and flood the log
			time.Sleep(readErrorBackoff)
			continue
		}
		if srcAddr == nil {
			continue
		}
		srcIp := srcAddr.IP.String()
		upTprt.Log.Infof("read %v bytes from %v:%v", n, srcIp, srcAddr.Port)

		gnbupf := upTprt.GnbInstance.GnbPeers.GetGnbUpf(srcIp)
		if gnbupf == nil {
			upTprt.Log.Errorln("no UPF Context found corresponding to IP:", srcIp)
			continue
		}
		tMsg := &common.TransportMessage{}
		tMsg.RawPkt = recvMsg[:n]
		gnbupf.ReadChan <- tMsg
		upTprt.Log.Debugln("forwarded UDP packet to UPF Worker")
	}
}

func (upTprt *GnbUpTransport) CheckTransportParam(peer transportcommon.TransportPeer,
	pkt []byte,
) error {
	upf := peer.(*gnbctx.GnbUpf)

	if upf == nil {
		return fmt.Errorf("UPF is nil")
	}

	if len(pkt) == 0 {
		return fmt.Errorf("packet len is 0")
	}

	if upf.UpfAddr == nil {
		return fmt.Errorf("UPF address is nil")
	}

	return nil
}

func (upTprt *GnbUpTransport) SendToPeerBlock(peer transportcommon.TransportPeer, pkt []byte, id uint64) ([]byte, error) {
	return nil, nil
}

func (upTprt *GnbUpTransport) ConnectToPeer(peer transportcommon.TransportPeer) error {
	return nil
}
