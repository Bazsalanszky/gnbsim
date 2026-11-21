// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"sync"
	"time"

	"github.com/omec-project/gnbsim/common"
	"github.com/omec-project/gnbsim/logger"
	"github.com/omec-project/openapi/v2/models"
	"go.uber.org/zap"
)

/* PduSession represents a PDU Session in Real UE. It listens for DL user data
 * packets from the gNB and also writes UL packets to gNB on the command of
 * Real UE control plane
 */
type PduSession struct {
	Snssai           models.Snssai
	WriteUeChan      chan common.InterfaceMessage
	ReadDlChan       chan common.InterfaceMessage
	ReadCmdChan      chan common.InterfaceMessage
	Log              *zap.SugaredLogger
	GenStop          chan struct{}
	WriteGnbChan     chan common.InterfaceMessage
	DefaultAs        string
	DefaultAsV6      string // the destination of the IPv6 echo requests
	PduSessType      models.PduSessionType
	RsTimer          *time.Timer // retransmits the router solicitation of a data request
	PduAddress       net.IP      // the IPv4 address of an IPv4 or IPv4v6 session
	Ipv6InterfaceId  []byte      // the 8-octet IPv6 interface identifier of an IPv6 or IPv4v6 session
	Ipv6Prefix       net.IP      // the /64 of the last usable router advertisement
	PingFamilies     []string    // the address families of one-off echo requests, pinged in turn
	Ipv6Address      net.IP      // the UE's IPv6 address: Ipv6Prefix and Ipv6InterfaceId
	RsSent           int         // router solicitations sent for the current data request
	RaReceived       int         // usable router advertisements
	RaSolicited      int         // of them, those sent to the UE's link-local address: answers to an RS
	PingPhase        int         // index in PingFamilies of the family being pinged
	PhaseTxCount     int         // echo requests sent in the current phase
	GenWg            sync.WaitGroup
	PktCount         int
	SeqNum           int
	ReqDataPktCount  int
	ReqDataPktInt    int
	TxDataPktCount   int
	RxDataPktCount   int
	PduSessId        int64
	SscMode          uint8
	LastDataPktRecvd bool
	Launched         bool
	DataPending      bool // a data request waits for a router advertisement
	PendingPTI       uint8
}

func NewPduSession(realUe *RealUe, pduSessId int64) *PduSession {
	pduSess := PduSession{}
	pduSess.PduSessId = pduSessId
	pduSess.ReadDlChan = make(chan common.InterfaceMessage, 10)
	pduSess.ReadCmdChan = make(chan common.InterfaceMessage, 10)
	pduSess.Log = realUe.Log.With("subcategory", "PduSession", logger.FieldPduSessId, pduSessId)
	pduSess.Log.Debugln("pdu session created")
	return &pduSess
}

func (pduSess *PduSession) GetNextSeqNum() int {
	pduSess.SeqNum++
	/* Allowing sequence number to always start from 1 */
	if pduSess.SeqNum <= 0 {
		pduSess.SeqNum = 1
	}
	return pduSess.SeqNum
}
