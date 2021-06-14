package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"finder.ink/proxy/app"
	"finder.ink/proxy/protocol"
)

func parseArgs() (app.Config, error) {
	var proto, destAddr, listen string
	var encrypt bool

	localCmd := flag.NewFlagSet("local", flag.ExitOnError)
	localCmd.StringVar(&proto, "protocol", "socks5", "proxy protocol: [socks5|ss|private|pass]")
	localCmd.BoolVar(&encrypt, "encrypt", false, "encrypt or not")
	localCmd.StringVar(&destAddr, "destination", "", "destination address: [ip:port]")
	localCmd.StringVar(&listen, "listen", "0.0.0.0:1080", "listen address: [ip:port]")

	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverCmd.StringVar(&proto, "protocol", "socks5", "proxy protocol: [socks5|ss|private|pass]")
	serverCmd.BoolVar(&encrypt, "encrypt", false, "encrypt or not")
	serverCmd.StringVar(&listen, "listen", "0.0.0.0:1080", "listen address: [ip:port]")

	var config app.Config
	if len(os.Args) < 2 {
		return config, errors.New("expected 'server' or 'local' commands")
	}

	switch os.Args[1] {
	case "local":
		localCmd.Parse(os.Args[2:])
		config.RemoteAddr = destAddr
		config.Deploy = protocol.DEPLOY_LOCAL
	case "server":
		serverCmd.Parse(os.Args[2:])
		config.Deploy = protocol.DEPLOY_SERVER
	default:
		return config, fmt.Errorf("unknow subcommand: %s, expected [local|server]", os.Args[1])
	}

	config.Encrypt = encrypt
	config.Listen = listen
	switch proto {
	case "socks5":
		config.Protocol = protocol.PROTO_SOCKS5
	case "ss":
		config.Protocol = protocol.PROTO_SS
	case "private":
		config.Protocol = protocol.PROTO_PRIVATE
	case "pass":
		config.Protocol = protocol.PROTO_PASS
	default:
		return config, fmt.Errorf("unknow protocol: %s", proto)
	}

	return config, nil
}

func main() {
	config, err := parseArgs()
	if err != nil {
		println("args error:", err.Error())
		os.Exit(1)
	}
	fmt.Printf("%+v\n", config)
	server, err := app.NewServer(config)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	server.Run()
}
