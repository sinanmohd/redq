// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package db

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type Dnsblacklist struct {
	Name string
}

type Macblacklist struct {
	Hardwareaddr int64
}

type Usage struct {
	Hardwareaddr int64
	Starttime    pgtype.Timestamp
	Stoptime     pgtype.Timestamp
	Egress       int64
	Ingress      int64
}
