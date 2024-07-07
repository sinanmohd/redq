package api

import (
	"context"
	"encoding/json"
	"log"
	"net"

	"github.com/dustin/go-humanize"
	"sinanmohd.com/redq/db"
	"sinanmohd.com/redq/usage"
)

type UsageStat struct {
	Ingress string `json:"ingress"`
	Egress  string `json:"egress"`
}

type UsageResp map[string]UsageStat

func handleUsage(conn net.Conn, u *usage.Usage, queries *db.Queries, ctxDb context.Context) {
	resp := make(UsageResp)

	fetchedUsage, err := queries.GetUsage(ctxDb)
	if err != nil {
		log.Printf("fetching from database: %s", err)
		return
	}

	u.Mutex.RLock()
	for _, value := range u.Data {
		fetchedUsage.Ingress += int64(value.Ingress)
		fetchedUsage.Egress += int64(value.Egress)
	}
	u.Mutex.RUnlock()
	resp["total"] = UsageStat{
		Ingress: humanize.Bytes(uint64(fetchedUsage.Ingress)),
		Egress:  humanize.Bytes(uint64(fetchedUsage.Egress)),
	}

	buf, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshaling json: %s", err)
		return
	}

	conn.Write(buf)
}
