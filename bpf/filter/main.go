package filter

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"sinanmohd.com/redq/db"
)

type Filter struct {
	ctxDb context.Context
	queries *db.Queries
	objs bpfObjects
	xdpLink link.Link
}

func Close(f *Filter) {
	f.objs.Close()
	f.xdpLink.Close()
}

func New(iface *net.Interface, queries *db.Queries, ctxDb context.Context) (*Filter, error) {
	var err error
	var f Filter

	if err := loadBpfObjects(&f.objs, nil); err != nil {
		log.Printf("loading objects: %s", err)
		return nil, err
	}
	defer func() {
		if err != nil {
			f.objs.Close()
		}
	}()

	f.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   f.objs.MacFilter,
	})
	if err != nil {
		log.Printf("could not attach TCx program: %s", err)
		return nil, err
	}
	defer func() {
		if err != nil {
			f.xdpLink.Close()
		}
	}()

	blackList, err := queries.GetMacBlackList(ctxDb)
	zeros := make([]uint16, len(blackList))
	_, err = f.objs.bpfMaps.MacBlacklistMap.BatchUpdate(blackList[:], zeros, nil)
	if err != nil {
		log.Printf("loading mac blacklist: %s", err)
		return nil, err
	}

	f.queries = queries
	return &f, nil
}

func (f *Filter) Block(mac uint64) error {
	err := f.queries.EnterMacBlackList(f.ctxDb, int64(mac))
	if err != nil {
		log.Printf("adding mac blacklist: %s", err)
		return err
	}

	err = f.objs.bpfMaps.MacBlacklistMap.Put(mac, true)
	if err != nil {
		log.Printf("adding mac blacklist: %s", err)
		return err
	}

	return nil
}

func (f *Filter) Unblock(mac uint64) error {
	err := f.queries.DeleteDnsBlackList(f.ctxDb, fmt.Sprintf("%v", mac))
	if err != nil {
		log.Printf("adding mac blacklist: %s", err)
		return err
	}

	err = f.objs.bpfMaps.MacBlacklistMap.Delete(mac)
	if err != nil {
		log.Printf("adding mac blacklist: %s", err)
		return err
	}

	return nil
}
