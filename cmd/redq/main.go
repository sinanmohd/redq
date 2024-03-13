package main

import (
	"log"

	redqapi "sinanmohd.com/redq/api"
	redqdb "sinanmohd.com/redq/db"
)

func main() {
	db, err := redqdb.NewSafeDB()
	if err != nil {
		log.Fatal(err)
	}

	redqapi.Run(db)
}
