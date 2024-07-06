package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"
	"sinanmohd.com/redq/db"
	"sinanmohd.com/redq/api"
	"sinanmohd.com/redq/usage"
)

func main() {
	var u usage.Usage
	var a api.Api

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

	err = a.Init()
	if err != nil {
		os.Exit(0)
	}
	err = u.Init(iface)
	if err != nil {
		os.Exit(0)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func() {
		<-sigs
		u.CleanUp(queries, ctx)
		a.CleanUp()
		os.Exit(0)
	}()

	go u.Run(iface, queries, ctx)
	a.Run(&u)
}
