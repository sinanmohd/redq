package api

import (
	"encoding/json"
	"log"
	"net"

	"sinanmohd.com/redq/dns"
)

type DnsResp map[string]string

func handleDnsBlock(conn net.Conn, d *dns.Dns, domains []string) {
	resp := make(DnsResp)

	for _, domain := range domains {
		err := d.Block(domain)
		if err != nil {
			resp[domain] = err.Error()
		} else {
			resp[domain] = "blocked"
		}
	}

	buf, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshaling json: %s", err)
		return
	}

	conn.Write(buf)
}

func handleDnsUnblock(conn net.Conn, d *dns.Dns, domains []string) {
	resp := make(DnsResp)

	for _, domain := range domains {
		err := d.Unblock(domain)
		if err != nil {
			resp[domain] = err.Error()
		} else {
			resp[domain] = "unblocked"
		}
	}

	buf, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshaling json: %s", err)
		return
	}

	conn.Write(buf)
}

func handleDns(conn net.Conn, d *dns.Dns, domains []string, action string) {
	switch action {
	case "block":
		handleDnsBlock(conn, d, domains)
	case "unblock":
		handleDnsUnblock(conn, d, domains)
	default:
		log.Printf("handling dns: invalid action '%s'", action)
	}
}
