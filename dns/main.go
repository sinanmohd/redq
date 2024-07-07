package dns

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/miekg/dns"
	"sinanmohd.com/redq/db"
)

type DnsBlackList struct {
	data  map[string]bool
	mutex sync.RWMutex
}

type Dns struct {
	server    dns.Server
	config    *dns.ClientConfig
	queries   *db.Queries
	ctxDb     context.Context
	blackList DnsBlackList
}

func (d *Dns) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	var resp *dns.Msg
	var err error

	d.blackList.mutex.RLock()
	for _, qustion := range req.Question {
		_, ok := d.blackList.data[qustion.Name]
		if ok == false {
			continue
		}

		resp = new(dns.Msg)
		resp.SetReply(req)
		w.WriteMsg(resp)
		return
	}
	d.blackList.mutex.RUnlock()

	client := new(dns.Client)
	req.RecursionDesired = true
	for _, upstream := range d.config.Servers {
		resp, _, err = client.Exchange(req, net.JoinHostPort(upstream, d.config.Port))
		if err == nil {
			break
		}

		log.Printf("dns resolving: %s", err)
	}
	if err != nil {
		return
	}

	w.WriteMsg(resp)
}

func New(queries *db.Queries, ctxDb context.Context) (*Dns, error) {
	var d Dns
	var err error

	d.server = dns.Server{
		Net:       "udp",
		ReusePort: true,
		Handler:   &d,
	}

	d.config, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Printf("reading resolve.conf: %s", err)
		return nil, err
	}

	d.queries = queries
	d.ctxDb = ctxDb
	d.blackList.data = make(map[string]bool)
	blackList, err := d.queries.GetDnsBlackList(d.ctxDb)
	if err != nil {
		log.Printf("reading dns blacklist database: %s", err)
		return nil, err
	}
	for _, entry := range blackList {
		d.blackList.data[entry] = true
	}

	return &d, nil
}

func (d *Dns) Run() {
	d.server.ListenAndServe()
}
