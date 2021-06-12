package server

import (
	"net"

	socks5 "finder.ink/proxy/protocol"
)

type Server struct {
	address  string
	listener net.Listener
}

func NewServer(addr string) (*Server, error) {
	var server Server
	var err error
	server.address = addr
	server.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return &server, err
	}

	return &server, nil
}

func (p *Server) Run() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			println("accept error", err.Error())
			continue
		}

		println("accept from", conn.RemoteAddr().String())
		go p.protocolHandshake(conn)
	}
}

func (p *Server) transfer(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()

	buff := make([]byte, 0x10000)
	for {
		n, err := src.Read(buff)
		if err != nil {
			return
		}

		for i := 0; i < n; {
			m, err := dst.Write(buff[i:n])
			if err != nil {
				return
			}
			i += m
		}
	}
}

func (p *Server) protocolHandshake(conn net.Conn) {
	err := socks5.AuthMethod(conn)
	if err != nil {
		println(err.Error())
		return
	}

	remote_addr, err := socks5.ProcessRequest(conn)
	if err != nil {
		println(err.Error())
		return
	}
	println(remote_addr)

	remote_conn, err := net.Dial("tcp", remote_addr)
	if err != nil {
		println(err.Error())
		return
	}

	go p.transfer(conn, remote_conn)
	p.transfer(remote_conn, conn)
}
