package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type Socks5Auth struct {
	Ver     uint8
	Nmethod uint8
}

type Socks5AuthReply struct {
	Ver    uint8
	Method uint8
}

type Socks5Request struct {
	Ver         uint8
	Cmd         uint8
	Reserved    uint8
	AddressType uint8
}

type Socks5RequestReply struct {
	Ver     uint8
	Rsp     uint8
	Rsv     uint8
	Atype   uint8
	BndAddr uint32
	BndPort uint16
}

type Socks5Protocol struct {
	conn   net.Conn
	auth   Socks5Auth
	req    Socks5Request
	buff   []byte
	Config ProtoConfig
}

func NewSocks5(conn net.Conn, config ProtoConfig) *Socks5Protocol {
	return &Socks5Protocol{conn: conn, Config: config, buff: make([]byte, 512)}
}

// parse socks5 proto address, return ip, port, err
func (p *Socks5Protocol) parseAddress(atype uint8, data []byte) (string, uint16, error) {
	var addr string
	var port uint16

	if atype == 1 {
		ipLong := binary.BigEndian.Uint32(data[:4])
		addr = long2IP(ipLong)
		port = binary.BigEndian.Uint16(data[4:6])
	} else if atype == 3 {
		alen := uint8(data[0])
		addr = string(data[1 : 1+alen])
		port = binary.BigEndian.Uint16(data[1+alen : 3+alen])
	} else {
		return "", 0, errors.New("not supported socks5 address type")
	}

	return addr, port, nil
}

func (p *Socks5Protocol) replyRequest(rsp uint8) error {
	reply := &Socks5RequestReply{
		Ver:     5,
		Rsp:     rsp,
		Rsv:     0,
		Atype:   1,
		BndAddr: 0, // ignore
		BndPort: 0, // ignore
	}

	err := binary.Write(p.conn, binary.BigEndian, reply)
	if err != nil {
		return err
	}
	return nil
}

func (p *Socks5Protocol) authMethod() error {
	n, err := p.conn.Read(p.buff)
	if err != nil {
		return err
	}
	authReader := bytes.NewReader(p.buff)

	err = binary.Read(authReader, binary.BigEndian, &p.auth)
	if err != nil {
		return err
	}

	if p.auth.Ver != 5 || p.auth.Nmethod == 0 {
		return errors.New("auth ver or nmethod error")
	}

	authMethod := p.buff[2:n]
	if !bytes.Contains(authMethod, []byte{0}) {
		return errors.New("no support auth method")
	}

	reply := &Socks5AuthReply{
		Ver:    5,
		Method: 0,
	}

	err = binary.Write(p.conn, binary.BigEndian, reply)
	if err != nil {
		return err
	}

	return nil
}

// return request address
func (p *Socks5Protocol) processRequest() ([]byte, error) {
	n, err := p.conn.Read(p.buff)
	if err != nil {
		return nil, err
	}

	reqReader := bytes.NewReader(p.buff)
	err = binary.Read(reqReader, binary.BigEndian, &p.req)
	if err != nil {
		return nil, err
	}

	if p.req.Ver != 5 || p.req.Cmd != 1 {
		return nil, errors.New("request ver or cmd error")
	}

	return p.buff[4:n], nil
}

func (p *Socks5Protocol) deployServer(data []byte) (net.Conn, error) {
	// deploy server connect
	addr, port, err := p.parseAddress(p.req.AddressType, data)
	if err != nil {
		return nil, err
	}
	ip := addr
	if p.req.AddressType == 3 {
		ip, err = queryDns(addr)
		if err != nil {
			return nil, err
		}
	}

	tcpAddr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *Socks5Protocol) deployLocal(data []byte) (net.Conn, error) {
	conn, err := net.Dial("tcp", p.Config.RemoteAddr)
	if err != nil {
		return nil, err
	}
	addrBuff := make([]byte, 256)

	var privateHeader PrivateProtoHeader
	// parse address
	addr, port, err := p.parseAddress(p.req.AddressType, data)
	if err != nil {
		return nil, err
	}

	xorKey := uint32(time.Now().Unix()) % 255
	privateHeader.Port = port
	privateHeader.XorKey = xorKey
	p.Config.Encryptor.XorKey = uint8(xorKey) // ser xor key for app

	if p.req.AddressType == 1 {
		privateHeader.AddrLen = 4
		privateHeader.Type = PRIVATE_V4_ADDR
		binary.BigEndian.PutUint32(addrBuff, ip2Long(addr))
		addrBuff = addrBuff[:4]
	} else if p.req.AddressType == 3 {
		privateHeader.AddrLen = uint8(len(addr))
		privateHeader.Type = PRIVATRE_DOMAIN_ADDR
		addrBuff = []byte(addr)
	} else {
		return nil, fmt.Errorf("unsupported address type: %d", p.req.AddressType)
	}

	binBuffer := &bytes.Buffer{}
	binary.Write(binBuffer, binary.BigEndian, privateHeader)
	encryptBuffer := append(binBuffer.Bytes(), addrBuff...)
	if p.Config.Encrypt {
		p.Config.Encryptor.NaiveEncrypt(encryptBuffer)
	}

	_, err = conn.Write(encryptBuffer)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *Socks5Protocol) HandShake() (net.Conn, error) {
	err := p.authMethod()
	if err != nil {
		return nil, err
	}

	data, err := p.processRequest()
	if err != nil {
		return nil, err
	}
	var remoteConn net.Conn
	if p.Config.Deploy == DEPLOY_SERVER {
		remoteConn, err = p.deployServer(data)
	} else if p.Config.Deploy == DEPLOY_LOCAL {
		remoteConn, err = p.deployLocal(data)
	}
	if err != nil {
		p.replyRequest(1)
		return nil, err
	}

	err = p.replyRequest(0)
	if err != nil {
		return nil, err
	}

	return remoteConn, nil
}
