package dns

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

type Dns struct {
	server dns.Server
	config *dns.ClientConfig
}

func (d *Dns) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	var resp *dns.Msg
	var err error
	client := new(dns.Client)

	req.RecursionDesired = true;
	for _, upstream := range d.config.Servers {
		resp, _, err = client.Exchange(req, net.JoinHostPort(upstream, d.config.Port))
		if err == nil {
			break
		}

		log.Printf("dns query: %s", err)
	}

	w.WriteMsg(resp)
}

func New() (*Dns, error) {
	var d Dns
	var err error

	d.server = dns.Server{
		Net: "udp",
		ReusePort: true,
		Handler: &d,
	}

	d.config, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Printf("reading resolve.conf: %s", err)
		return nil, err
	}

	return &d, nil
}

func (d *Dns) Run() {
	d.server.ListenAndServe()
}
