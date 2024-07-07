package api

import (
	"encoding/json"
	"log"
	"net"

	"sinanmohd.com/redq/usage"
)

const (
	sockPath = "/tmp/redq_ebpf.sock"
	bufSize  = 4096
)

type ApiReq struct {
	Type   string `json:"type"`
	Action string `json:"action"`
	Arg    string `json:"arg"`
}

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

		go handleConn(conn, u)
	}
}

func handleConn(conn net.Conn, u *usage.Usage) {
	defer conn.Close()
	var req ApiReq
	buf := make([]byte, bufSize)

	count, err := conn.Read(buf)
	if err != nil {
		log.Printf("reading to buffer: %s", err)
		return
	}

	err = json.Unmarshal(buf[:count], &req)
	if err != nil {
		log.Printf("unmarshaling json: %s", err)
		return
	}

	switch req.Type {
	case "bandwidth":
		handleBandwidth(conn, u)
	default:
		log.Printf("invalid request type: %s", req.Type)
	}
}
