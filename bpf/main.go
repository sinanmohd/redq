package bpf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jackc/pgx/v5/pgtype"
	"sinanmohd.com/redq/db"
)

type UsageStat struct {
	lastSeen   time.Time
	lastDbPush time.Time
	ingress    uint64
	egress     uint64
}
type UsageMap map[uint32]UsageStat

func Run(iface *net.Interface, queries *db.Queries, ctxDb context.Context) {
	usageMap := make(UsageMap)

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer ingressLink.Close()

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer egressLink.Close()

	bpfTicker := time.NewTicker(1 * time.Second)
	defer bpfTicker.Stop()
	dbTicker := time.NewTicker(60 * time.Second)
	defer dbTicker.Stop()
	for {
		select {
		case <-bpfTicker.C:
			usageMap.update(objs.IngressIp4UsageMap, objs.EgressIp4UsageMap)
		case <-dbTicker.C:
			usageMap.dbPush(queries, ctxDb)
			continue
		}
	}
}

func (usageStat UsageStat) expired(timeStart *time.Time) bool {
	timeDiff := timeStart.Sub(usageStat.lastSeen)
	if timeDiff > time.Minute {
		return true
	}

	timeDiff = timeStart.Sub(usageStat.lastDbPush)
	if timeDiff > time.Hour {
		return true
	}

	return false
}

func (usageMap UsageMap) dbPush(queries *db.Queries, ctxDb context.Context) {
	timeStart := time.Now()

	for key, value := range usageMap {
		if !value.expired(&timeStart) {
			continue
		}

		err := queries.EnterUsage(ctxDb, db.EnterUsageParams{
			Hardwareaddr: int32(key),
			Starttime: pgtype.Timestamp{
				Time:  value.lastDbPush,
				Valid: true,
			},
			Stoptime: pgtype.Timestamp{
				Time:  value.lastSeen,
				Valid: true,
			},
			Egress:  int32(value.egress),
			Ingress: int32(value.ingress),
		})
		if err != nil {
			log.Println(err)
		}

		delete(usageMap, key)
	}
}

func (usageMap UsageMap) update(ingress *ebpf.Map, egress *ebpf.Map) {
	timeStart := time.Now()
	batchKeys := make([]uint32, 4096)
	batchValues := make([]uint64, 4096)
	var key uint32

	cursor := ebpf.MapBatchCursor{}
	for {
		_, err := ingress.BatchLookupAndDelete(&cursor, batchKeys, batchValues, nil)
		for i := range batchKeys {
			key = batchKeys[i]
			usage, ok := usageMap[key]
			if ok {
				usage.ingress += batchValues[i]
				usage.lastSeen = timeStart
				usageMap[key] = usage
			} else {
				usageMap[key] = UsageStat{
					ingress:    batchValues[i],
					lastDbPush: timeStart,
					lastSeen:   timeStart,
				}
			}
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			fmt.Println(err)
			break
		}
	}

	cursor = ebpf.MapBatchCursor{}
	for {
		_, err := egress.BatchLookupAndDelete(&cursor, batchKeys, batchValues, nil)
		for i := range batchKeys {
			key = batchKeys[i]
			usage, ok := usageMap[key]
			if ok {
				usage.egress += batchValues[i]
				usage.lastSeen = timeStart
				usageMap[key] = usage
			} else {
				usageMap[key] = UsageStat{
					egress:     batchValues[i],
					lastDbPush: timeStart,
					lastSeen:   timeStart,
				}
			}
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			fmt.Println(err)
			break
		}
	}
}
