package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"
	"sinanmohd.com/redq/api"
	"sinanmohd.com/redq/db"
	"sinanmohd.com/redq/dns"
	"sinanmohd.com/redq/bpf/usage"
	"sinanmohd.com/redq/bpf/filter"
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

	d, err := dns.New(queries, ctx)
	if err != nil {
		os.Exit(0)
	}
	a, err := api.New()
	if err != nil {
		os.Exit(0)
	}
	f, err := filter.New(iface, queries, ctx)
	if err != nil {
		os.Exit(0)
	}
	u, err := usage.New(iface)
	if err != nil {
		os.Exit(0)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func() {
		<-sigs
		usage.Close(u, queries, ctx)
		filter.Close(f)
		api.Close(a)
		os.Exit(0)
	}()

	go u.Run(iface, queries, ctx)
	go d.Run()

	a.Run(u, d, f, queries, ctx)
}
