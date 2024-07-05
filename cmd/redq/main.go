package main

import (
	"context"
	"log"
	"net"

	"github.com/jackc/pgx/v5"
	"sinanmohd.com/redq/bpf"
	"sinanmohd.com/redq/db"
)

func main() {
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

	bpf.Run(iface, queries, ctx)
}
