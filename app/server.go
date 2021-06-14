package app

import (
	"net"

	"finder.ink/proxy/encrypt"
	"finder.ink/proxy/protocol"
)

type Server struct {
	listener    net.Listener
	config      Config
	recvDecrypt bool
	sendEncrypt bool
	encryptor   encrypt.Encryptor
}

func NewServer(config Config) (*Server, error) {
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}
	srv := &Server{
		listener: listener,
		config:   config,
	}

	if config.Deploy == protocol.DEPLOY_SERVER && config.Encrypt {
		srv.recvDecrypt = true
		srv.sendEncrypt = false
	}

	if config.Deploy == protocol.DEPLOY_LOCAL && config.Encrypt {
		srv.sendEncrypt = true
		srv.recvDecrypt = false
	}

	return srv, nil
}

func (p *Server) Run() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			println("accept error", err.Error())
			continue
		}

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
		if p.recvDecrypt {
			p.encryptor.Decrypt(buff[:n])
		}
		if p.sendEncrypt {
			p.encryptor.Encrypt(buff[:n])
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
	var proto protocol.Protocol
	pConfig := protocol.ProtoConfig{
		Deploy:     p.config.Deploy,
		RemoteAddr: p.config.RemoteAddr,
		Encrypt:    p.config.Encrypt,
		Encryptor:  &p.encryptor,
	}

	switch p.config.Protocol {
	case protocol.PROTO_SOCKS5:
		proto = protocol.NewSocks5(conn, pConfig)
	case protocol.PROTO_PRIVATE:
		proto = protocol.NewPrivate(conn, pConfig)
	case protocol.PROTO_SS:
		proto = protocol.NewSS(conn, pConfig)
	case protocol.PROTO_PASS:
		proto = protocol.NewPass(conn, pConfig)
	default:
		println("unsupport protocol")
		return
	}

	remoteConn, err := proto.HandShake()
	if err != nil {
		println("socks5 handshake failed", err.Error())
		return
	}

	go p.transfer(conn, remoteConn)
	p.transfer(remoteConn, conn)
}
