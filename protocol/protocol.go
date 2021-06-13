package protocol

import (
	"encoding/binary"
	"net"
)

type Protocol interface {
	HandShake() (net.Conn, error)
}

type DeployType uint8
type ProtoType uint8

const (
	DEPLOY_LOCAL  DeployType = 0
	DEPLOY_SERVER DeployType = 1
)

func (p DeployType) String() string {
	switch p {
	case DEPLOY_LOCAL:
		return "DEPLOY_LOCAL"
	case DEPLOY_SERVER:
		return "DEPLOY_SERVER"
	default:
		return "UNKNOW"
	}
}

const (
	PROTO_PASS    ProtoType = 0
	PROTO_SOCKS5  ProtoType = 1
	PROTO_SS      ProtoType = 2
	PROTO_PRIVATE ProtoType = 3
)

func (p ProtoType) String() string {
	switch p {
	case PROTO_PASS:
		return "PROTO_PASS"
	case PROTO_SOCKS5:
		return "PROTO_SOCKS5"
	case PROTO_SS:
		return "PROTO_SS"
	case PROTO_PRIVATE:
		return "PROTO_PRIVATE"
	default:
		return "UNKNOW"
	}
}

const (
	PRIVATE_V4_ADDR      uint8 = 1
	PRIVATRE_DOMAIN_ADDR uint8 = 2
)

type ProtoConfig struct {
	Deploy     DeployType
	RemoteAddr string
	Encrypt    bool
}

// common function
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
