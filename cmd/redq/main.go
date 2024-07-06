package main

import (
	"context"
	"log"
	"net"

	"github.com/jackc/pgx/v5"
	"sinanmohd.com/redq/usage"
	"sinanmohd.com/redq/db"
)

func main() {
	u := &usage.Usage {
		Data : make(usage.UsageMap),
	}

	iface, err := net.InterfaceByName("wlan0")
	if err != nil {
		log.Fatalf("lookup network: %s", err)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "user=redq_ebpf dbname=redq_ebpf")
	if err != nil {
		log.Fatalf("connecting database: %s", err)
	}
	defer conn.Close(ctx)
	queries := db.New(conn)

	u.Run(iface, queries, ctx)
}
