package usage

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jackc/pgx/v5/pgtype"
	"sinanmohd.com/redq/db"
)

type usageStat struct {
	lastSeen         time.Time
	lastDbPush       time.Time
	BandwidthIngress uint64
	BandwidthEgress  uint64
	Ingress          uint64
	Egress           uint64
}

type usageMap map[uint64]usageStat
type Usage struct {
	Data                    usageMap
	Mutex                   sync.Mutex
	objs                    bpfObjects
	egressLink, ingressLink link.Link
}

func (u *Usage) Init(iface *net.Interface) error {
	var err error

	if err := loadBpfObjects(&u.objs, nil); err != nil {
		log.Printf("loading objects: %s", err)
		return err
	}
	defer func() {
		if err != nil {
			u.objs.Close()
		}
	}()

	u.ingressLink, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   u.objs.IngressFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Printf("could not attach TCx program: %s", err)
		return err
	}
	defer func() {
		if err != nil {
			u.ingressLink.Close()
		}
	}()

	u.egressLink, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   u.objs.EgressFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("could not attach TCx program: %s", err)
		return err
	}

	u.Data = make(usageMap)
	return nil
}

func (u *Usage) CleanUp(queries *db.Queries, ctxDb context.Context) {
	err := u.UpdateDb(queries, ctxDb, false)
	if err != nil {
		log.Printf("updating Database: %s", err)
	}

	u.objs.Close()
	u.ingressLink.Close()
	u.egressLink.Close()
}

func (u *Usage) Run(iface *net.Interface, queries *db.Queries, ctxDb context.Context) {
	bpfTicker := time.NewTicker(time.Second)
	defer bpfTicker.Stop()
	dbTicker := time.NewTicker(time.Minute)
	defer dbTicker.Stop()

	for {
		select {
		case <-bpfTicker.C:
			err := u.update(u.objs.IngressIp4UsageMap, u.objs.EgressIp4UsageMap)
			if err != nil {
				log.Printf("updating usageMap: %s", err)
			}
		case <-dbTicker.C:
			err := u.UpdateDb(queries, ctxDb, true)
			if err != nil {
				log.Printf("updating Database: %s", err)
			}
		}
	}
}

func (us *usageStat) expired(timeStart *time.Time) bool {
	timeDiff := timeStart.Sub(us.lastSeen)
	if timeDiff > time.Minute {
		return true
	}

	timeDiff = timeStart.Sub(us.lastDbPush)
	if timeDiff > time.Hour {
		return true
	}

	return false
}

func (u *Usage) UpdateDb(queries *db.Queries, ctxDb context.Context, ifExpired bool) error {
	timeStart := time.Now()

	u.Mutex.Lock()
	for key, value := range u.Data {
		if ifExpired && !value.expired(&timeStart) {
			continue
		}

		err := queries.EnterUsage(ctxDb, db.EnterUsageParams{
			Hardwareaddr: int64(key),
			Starttime: pgtype.Timestamp{
				Time:  value.lastDbPush,
				Valid: true,
			},
			Stoptime: pgtype.Timestamp{
				Time:  value.lastSeen,
				Valid: true,
			},
			Egress:  int64(value.Egress),
			Ingress: int64(value.Ingress),
		})
		if err != nil {
			return err
		}

		delete(u.Data, key)
	}
	u.Mutex.Unlock()

	return nil
}

func (u *Usage) update(ingress *ebpf.Map, egress *ebpf.Map) error {
	timeStart := time.Now()
	batchKeys := make([]uint64, 4096)
	batchValues := make([]uint64, 4096)
	var key uint64

	cursor := ebpf.MapBatchCursor{}
	for {
		_, err := ingress.BatchLookupAndDelete(&cursor, batchKeys, batchValues, nil)
		for i := range batchKeys {
			/* TODO: maybe BatchLookupAndDelete is not the best idea with mostly empty map */
			if batchValues[i] == 0 {
				continue
			}

			key = batchKeys[i]
			u.Mutex.Lock()
			usage, ok := u.Data[key]
			if ok {
				usage.BandwidthIngress = batchValues[i] - usage.Ingress
				usage.Ingress += batchValues[i]
				usage.lastSeen = timeStart
				u.Data[key] = usage
			} else {
				u.Data[key] = usageStat{
					BandwidthIngress: batchValues[i],
					Ingress:          batchValues[i],
					lastDbPush:       timeStart,
					lastSeen:         timeStart,
				}
			}
			u.Mutex.Unlock()
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			return err
		}
	}

	cursor = ebpf.MapBatchCursor{}
	for {
		_, err := egress.BatchLookupAndDelete(&cursor, batchKeys, batchValues, nil)
		for i := range batchKeys {
			/* TODO: maybe BatchLookupAndDelete is not the best idea with mostly empty map */
			if batchValues[i] == 0 {
				continue
			}

			key = batchKeys[i]
			u.Mutex.Lock()
			usage, ok := u.Data[key]
			if ok {
				usage.BandwidthEgress = batchValues[i] - usage.Egress
				usage.Egress += batchValues[i]
				usage.lastSeen = timeStart
				u.Data[key] = usage
			} else {
				u.Data[key] = usageStat{
					BandwidthEgress: batchValues[i],
					Egress:          batchValues[i],
					lastDbPush:      timeStart,
					lastSeen:        timeStart,
				}
			}
			u.Mutex.Unlock()
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}
