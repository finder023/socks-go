package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
)

type Auth struct {
	Ver     uint8
	Nmethod uint8
}

type AuthReply struct {
	Ver    uint8
	Method uint8
}

type Request struct {
	Ver         uint8
	Cmd         uint8
	Reserved    uint8
	AddressType uint8
}

type RequestReply struct {
	Ver     uint8
	Rsp     uint8
	Rsv     uint8
	Atype   uint8
	BndAddr uint32
	BndPort uint16
}

func long2IP(ipLong uint32) string {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, ipLong)
	ip := net.IP(ipByte)
	return ip.String()
}

func ip2Long(ipAddr string) uint32 {
	ip := net.ParseIP(ipAddr)
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func queryDns(domain string) (string, error) {
	host, err := net.LookupHost(domain)
	if err != nil {
		return "", err
	}
	// pick first one
	return host[0], nil
}

func parseAddress(atype uint8, data []byte) (string, error) {
	var ip string
	var port uint16
	var err error

	if atype == 1 {
		ipLong := binary.BigEndian.Uint32(data[:4])
		ip = long2IP(ipLong)
		port = binary.BigEndian.Uint16(data[4:6])
	} else if atype == 3 {
		alen := uint8(data[0])
		domain := data[1 : 1+alen]
		ip, err = queryDns(string(domain))
		if err != nil {
			return "", err
		}
		port = binary.BigEndian.Uint16(data[1+alen : 3+alen])
	} else {
		return "", errors.New("not supported socks5 address type")
	}

	return fmt.Sprintf("%s:%d", ip, port), nil
}

func replyRequest(conn net.Conn, addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	reply := &RequestReply{
		Ver:     5,
		Rsp:     0,
		Rsv:     0,
		Atype:   1,
		BndAddr: ip2Long(tcpAddr.IP.String()),
		BndPort: uint16(tcpAddr.Port), // 应该传大端，应该也没啥问题
	}

	err = binary.Write(conn, binary.BigEndian, reply)
	if err != nil {
		return err
	}
	return nil
}

func AuthMethod(conn net.Conn) error {
	buff, err := ioutil.ReadAll(conn)
	if err != nil {
		return err
	}

	var auth Auth
	authReader := bytes.NewReader(buff)

	err = binary.Read(authReader, binary.BigEndian, &auth)
	if err != nil {
		return err
	}

	if auth.Ver != 5 || auth.Nmethod == 0 {
		return errors.New("auth ver or nmethod error")
	}

	authMethod := buff[2:]
	if !bytes.Contains(authMethod, []byte{0}) {
		return errors.New("no support auth method")
	}

	reply := &AuthReply{
		Ver:    5,
		Method: 0,
	}

	err = binary.Write(conn, binary.BigEndian, reply)
	if err != nil {
		return err
	}

	return nil
}

// return request address
func ProcessRequest(conn net.Conn) (string, error) {
	buff, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", err
	}

	var req Request
	reqReader := bytes.NewReader(buff)
	err = binary.Read(reqReader, binary.BigEndian, &req)
	if err != nil {
		return "", err
	}

	if req.Ver != 5 || req.Cmd != 1 {
		return "", errors.New("request ver or cmd error")
	}

	address, err := parseAddress(req.AddressType, buff[4:])
	if err != nil {
		return "", err
	}

	err = replyRequest(conn, address)
	if err != nil {
		return "", err
	}

	return address, nil
}
