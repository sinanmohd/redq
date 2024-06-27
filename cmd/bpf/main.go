package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Usage struct {
	ingress uint64
	egress uint64
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer ingressLink.Close()

	// Attach the program to Egress TC.
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer egressLink.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		prettyPrint(objs.IngressIp4UsageMap, objs.EgressIp4UsageMap)
	}
}

func prettyPrint(ingress *ebpf.Map, egress *ebpf.Map) {
	ipUsage := make(map[netip.Addr]Usage)
	var key netip.Addr
	var value uint64

	iter := ingress.Iterate()
	for iter.Next(&key, &value) {
		ipUsage[key] = Usage {
			ingress: value,
		}
	}

	iter = egress.Iterate()
	for iter.Next(&key, &value) {
		usage, ok := ipUsage[key]
		if (ok) {
			usage.egress = value
		} else {
			usage = Usage { egress: value }
		}

		ipUsage[key] = usage
	}

	fmt.Print("\033[H\033[2J")
	fmt.Printf("%15s\t%16s\t%16s\n", "ip", "down", "up")
	for ip4, usage := range ipUsage {
		fmt.Printf("%15s\t%16d\t%16d\n", ip4, usage.ingress, usage.egress)
	}
}
