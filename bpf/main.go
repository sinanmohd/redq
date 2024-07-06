package bpf

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
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
type UsageMap map[uint64]UsageStat

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

	bpfTicker := time.NewTicker(time.Second)
	defer bpfTicker.Stop()
	dbTicker := time.NewTicker(time.Minute)
	defer dbTicker.Stop()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill, syscall.SIGTERM)

	for {
		select {
		case <-bpfTicker.C:
			err := usageMap.update(objs.IngressIp4UsageMap, objs.EgressIp4UsageMap)
			if err != nil {
				log.Printf("updating usageMap: %s", err)
			}
		case <-sigs:
			err := usageMap.updateDb(queries, ctxDb, false)
			if err != nil {
				log.Printf("updating Database: %s", err)
			}
			os.Exit(0)
		case <-dbTicker.C:
			err := usageMap.updateDb(queries, ctxDb, true)
			if err != nil {
				log.Printf("updating Database: %s", err)
			}
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

func (usageMap UsageMap) updateDb(queries *db.Queries, ctxDb context.Context, ifExpired bool) error {
	timeStart := time.Now()

	for key, value := range usageMap {
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
			Egress:  int64(value.egress),
			Ingress: int64(value.ingress),
		})
		if err != nil {
			return err
		}

		delete(usageMap, key)
	}

	return nil
}

func (usageMap UsageMap) update(ingress *ebpf.Map, egress *ebpf.Map) error {
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
			return err
		}
	}

	return nil
}
