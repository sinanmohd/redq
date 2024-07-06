package api

import (
	"log"
	"net"

	"sinanmohd.com/redq/usage"
)

const sockPath = "/tmp/redq_ebpf.sock"

type Api struct {
	sock net.Listener
}

func Close(a *Api) {
	a.sock.Close()
}

func New() (*Api, error) {
	var err error
	var a Api

	a.sock, err = net.Listen("unix", sockPath)
	if err != nil {
		log.Printf("listening on unix socket: %s", err)
		return nil, err
	}

	return &a, nil
}

func (a *Api) Run(u *usage.Usage) {
	for {
		conn, err := a.sock.Accept()
		if err != nil {
			log.Printf("accepting connection: %s", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
}
