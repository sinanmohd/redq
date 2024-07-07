package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/cilium/cilium/pkg/mac"
	"github.com/dustin/go-humanize"
	"sinanmohd.com/redq/usage"
)

type BandwidthStat struct {
	Ingress string `json:"ingress"`
	Egress  string `json:"egress"`
}

type BandwidthResp map[string]BandwidthStat

func handleBandwidth(conn net.Conn, u *usage.Usage) {
	resp := make(BandwidthResp)

	u.Mutex.RLock()
	for key, value := range u.Data {
		m := mac.Uint64MAC(key)
		resp[m.String()] = BandwidthStat{
			Ingress: fmt.Sprintf("%s/s", humanize.Bytes(value.BandwidthIngress)),
			Egress:  fmt.Sprintf("%s/s", humanize.Bytes(value.BandwidthEgress)),
		}
	}
	u.Mutex.RUnlock()

	buf, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshaling json: %s", err)
		return
	}

	conn.Write(buf)
}
