package api

import (
	"encoding/json"
	"log"
	"net"

	"github.com/cilium/cilium/pkg/mac"
	"sinanmohd.com/redq/bpf/filter"
)

type FilterResp map[string]string

func handleFilterBlock(conn net.Conn, f *filter.Filter, macs []string) {
	resp := make(FilterResp)

	for _, mac_string := range macs {
		mac, err := mac.ParseMAC(mac_string)
		if err != nil {
			resp[mac_string] = err.Error()
			continue
		}

		mac_cilium64, err := mac.Uint64()
		if err != nil {
			resp[mac_string] = err.Error()
			continue
		}

		err = f.Block(uint64(mac_cilium64))
		if err != nil {
			resp[mac_string] = err.Error()
			continue
		}

		resp[mac_string] = "blocked"
	}

	buf, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshaling json: %s", err)
		return
	}

	conn.Write(buf)
}

func handleFilterUnblock(conn net.Conn, f *filter.Filter, macs []string) {
	resp := make(FilterResp)

	for _, mac_string := range macs {
		mac, err := mac.ParseMAC(mac_string)
		if err != nil {
			resp[mac_string] = err.Error()
			continue
		}

		mac_cilium64, err := mac.Uint64()
		if err != nil {
			resp[mac_string] = err.Error()
			continue
		}

		err = f.Unblock(uint64(mac_cilium64))
		if err != nil {
			resp[mac_string] = err.Error()
			continue
		}

		resp[mac_string] = "unblocked"
	}

	buf, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshaling json: %s", err)
		return
	}

	conn.Write(buf)
}

func handleFilter(conn net.Conn, f *filter.Filter, macs []string, action string) {
	switch action {
	case "block":
		handleFilterBlock(conn, f, macs)
	case "unblock":
		handleFilterUnblock(conn, f, macs)
	default:
		log.Printf("handling dns: invalid action '%s'", action)
	}
}
