package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/oiweiwei/gokrb5.fork/v9/iana/errorcode"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		//1 means we should always use TCP
		rb, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %v", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		//Try UDP first, TCP second
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}
	return rb, nil
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return r, err
	}
	r, err = cl.dialSendUDP(kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialSendUDP establishes a UDP connection to a KDC.
func (cl *Client) dialSendUDP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		conn, err := cl.settings.Dialer().Dial("udp", kdcs[i])
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			continue
		}
		// conn is guaranteed to be a UDPConn
		rb, err := sendUDP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn net.Conn, b []byte) ([]byte, error) {
	var r []byte
	defer conn.Close()
	pktConn, ok := conn.(net.PacketConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a UDP connection")
	}
	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %v", conn.RemoteAddr().String(), err)
	}
	udpbuf := make([]byte, 4096)
	n, _, err := pktConn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %v", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return r, err
	}
	r, err = cl.dialSendTCP(kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialKDCTCP establishes a TCP connection to a KDC.
func (cl *Client) dialSendTCP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		conn, err := cl.settings.Dialer().Dial("tcp", kdcs[i])
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			continue
		}
		// conn is guaranteed to be a TCPConn
		rb, err := sendTCP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn net.Conn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4, 4)
	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
