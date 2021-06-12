package main

import (
	"finder.ink/proxy/server"
)


func main() {
	server, err := server.NewServer("127.0.0.1:1080")
	if err != nil {
		println(err.Error())
		return
	}

	server.Run()
}
