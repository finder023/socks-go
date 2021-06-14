package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

/*
 * Shadowsocks TCP Relay Header:
 *
 *    +------+----------+----------+
 *    | ATYP | DST.ADDR | DST.PORT |
 *    +------+----------+----------+
 *    |  1   | Variable |    2     |
 *    +------+----------+----------+
 *
 */


type SSHeaderV4 struct {
	Ip uint32
	Port uint16
}

type SSProtocol struct {
	Conn net.Conn
	Config ProtoConfig
}


func NewSS(conn net.Conn, config ProtoConfig) *SSProtocol {
	return &SSProtocol{Conn: conn, Config: config}
}


func (p *SSProtocol) parseAddress() (uint8, string, uint16, error) {
	atypeByte := []byte{0}
	_, err := p.Conn.Read(atypeByte)
	if err != nil {
		return 0, "", 0, nil
	}

	atype := atypeByte[0]	
	var addr string
	var port uint16 
	if atype == 1 {
		var v4Header SSHeaderV4
		err = binary.Read(p.Conn, binary.BigEndian, &v4Header)
		if err != nil {
			return 0, "", 0, err
		}
		addr = long2IP(v4Header.Ip)
		port = v4Header.Port
	} else if atype == 3 {
		// domain addr
		lenByte := []byte{0}
		_, err = p.Conn.Read(lenByte)
		if err != nil {
			return 0, "", 0, err
		}
		domainLen := int(lenByte[0])
		domainBytes := make([]byte, domainLen + 2) // domain + port
		_, err = p.Conn.Read(domainBytes)
		if err != nil {
			return 0, "", 0, nil }
		addr = string(domainBytes[:domainLen])
		port = binary.BigEndian.Uint16(domainBytes[domainLen:])
	} else {
		return 0, "", 0, fmt.Errorf("unsupported ss addr type: %d", atype)
	}

	return atype, addr, port, nil
} 

func (p *SSProtocol) deployLocal(atype uint8, addr string, port uint16) (net.Conn, error) {
	conn, err := net.Dial("tcp", p.Config.RemoteAddr)
	if err != nil {
		return nil, err
	}

	var privateHeader PrivateProtoHeader
	addrBytes := make([]byte, 256)
	xorKey := uint32(time.Now().Unix()) % 256
	p.Config.Encryptor.XorKey = uint8(xorKey)

	if atype == 1 {
		// ip + port
		privateHeader.AddrLen = 4
		privateHeader.Type = PRIVATE_V4_ADDR
		binary.BigEndian.PutUint32(addrBytes, ip2Long(addr))
		addrBytes = addrBytes[:4]
	} else if atype == 3 {
		// domain addr type
		privateHeader.AddrLen = uint8(len(addr))
		privateHeader.Type = PRIVATRE_DOMAIN_ADDR
		addrBytes = []byte(addr)
	}

	binBytes := &bytes.Buffer{}
	binary.Write(binBytes, binary.BigEndian, privateHeader)
	encryptBuffer := append(binBytes.Bytes(), addrBytes...)
	if p.Config.Encrypt {
		p.Config.Encryptor.NaiveEncrypt(encryptBuffer)
	}

	_, err = conn.Write(encryptBuffer)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *SSProtocol) deployServer(atype uint8, addr string, port uint16) (net.Conn, error) {
	var err error
	ip := addr

	if atype == 3 {
		ip, err = queryDns(addr)
		if err != nil {
			return nil, err
		}
	}

	var tcpAddr = fmt.Sprintf("%s:%d", ip, port) 
	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}


func (p *SSProtocol) HandShake() (net.Conn, error) {
	atype, addr, port, err := p.parseAddress()
	if err != nil {
		return nil, err
	}

	var remoteConn net.Conn
	if p.Config.Deploy == DEPLOY_SERVER {
		remoteConn, err = p.deployServer(atype, addr, port)
	} else if p.Config.Deploy == DEPLOY_LOCAL {
		remoteConn, err = p.deployLocal(atype, addr, port)
	}
	if err != nil {
		return nil, err
	}

	return remoteConn, nil
}

