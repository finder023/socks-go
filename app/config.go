package app

import "finder.ink/proxy/protocol"

type Config struct {
	Deploy     protocol.DeployType
	Protocol   protocol.ProtoType
	Encrypt    bool
	RemoteAddr string
	Listen     string
}
