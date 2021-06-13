package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type PrivateProtoHeader struct {
	Port    uint16
	Type    uint8
	AddrLen uint8
	XorKey  uint32
}

type PrivateProtocol struct {
	Header PrivateProtoHeader
	Conn   net.Conn
	Config ProtoConfig
}

func NewPrivate(conn net.Conn, config ProtoConfig) *PrivateProtocol {
	// fmt.Printf("%+v\n", config)
	return &PrivateProtocol{Conn: conn, Config: config}
}

func (p *PrivateProtocol) processRequest() (string, error) {
	headerBytes := make([]byte, 8) // len(PrivatProtoHeader)
	_, err := p.Conn.Read(headerBytes)
	if err != nil {
		return "", err
	}

	if p.Config.Encrypt {
		p.Config.Encryptor.NaiveDecrypt(headerBytes)
	}

	headerBuff := bytes.NewBuffer(headerBytes)
	err = binary.Read(headerBuff, binary.BigEndian, &p.Header)
	if err != nil {
		return "", err
	}

	p.Config.Encryptor.XorKey = uint8(p.Header.XorKey)

	addrBuff := make([]byte, p.Header.AddrLen)
	for i := 0; i < int(p.Header.AddrLen); {
		n, err := p.Conn.Read(addrBuff)
		if err != nil {
			return "", err
		}
		i += n
	}

	if p.Config.Encrypt {
		p.Config.Encryptor.NaiveDecrypt(addrBuff)
	}

	var ipAddr string
	if p.Header.Type == PRIVATE_V4_ADDR {
		ip := net.IP(addrBuff[:4])
		ipAddr = ip.String()
	} else if p.Header.Type == PRIVATRE_DOMAIN_ADDR {
		ipAddr, err = queryDns(string(addrBuff))
		if err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("unknow private address type: %d", p.Header.Type)
	}

	v4Addr := fmt.Sprintf("%s:%d", ipAddr, p.Header.Port)
	return v4Addr, nil
}

func (p *PrivateProtocol) HandShake() (net.Conn, error) {
	addr, err := p.processRequest()
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
