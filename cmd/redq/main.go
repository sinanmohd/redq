package main

import (
	"log"
	"net"

	redqbpf "sinanmohd.com/redq/bpf"
)

func main() {
       iface, err := net.InterfaceByName("wlan0")
       if err != nil {
               log.Fatalf("lookup network: %s", err)
       }

	redqbpf.Run(iface)
}
