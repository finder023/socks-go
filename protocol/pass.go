package protocol

import "net"

type PassProtocol struct {
	Conn   net.Conn
	Config ProtoConfig
}

func NewPass(conn net.Conn, config ProtoConfig) *PassProtocol {
	return &PassProtocol{Conn: conn, Config: config}
}

func (p *PassProtocol) processRequest() (string, error) {
	return p.Config.RemoteAddr, nil
}

func (p *PassProtocol) HandShake() (net.Conn, error) {
	addr, _ := p.processRequest()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
