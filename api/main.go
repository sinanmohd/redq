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

func (a *Api) Init() error {
	var err error

	a.sock, err = net.Listen("unix", sockPath)
	if err != nil {
		log.Printf("listening on unix socket: %s", err)
		return err
	}

	return nil
}

func handleConn(conn net.Conn) {
	defer conn.Close()
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

func (a *Api) CleanUp() {
	a.sock.Close()
}
