package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	redqdb "sinanmohd.com/redq/db"
)

func help() {
	const helpString string =
`redqctl is a tool for managing redq.

Usage:

        redqctl <command> [arguments]

The commands are:

        create	create a redq account
        help	show this help cruft

`

	fmt.Print(helpString)
}

func create(args []string, db *redqdb.SafeDB) {
	f := flag.NewFlagSet("create", flag.ExitOnError)
	ac := &redqdb.Account{}
	ac.Info = &redqdb.Login{}

	f.StringVar(&ac.UserName, "username", "",
		"The username to associate with the account")
	f.StringVar(&ac.Info.FirstName, "fname", "",
		"The first name to associate with the account")
	f.StringVar(&ac.Info.LastName, "lname", "",
		"The last name to associate with the account")
	f.StringVar(&ac.Password, "pass", "",
		"The password to associate with the account")
	f.UintVar(&ac.Info.Level, "level", 0,
		"The level to associate with the account")
	f.Parse(args)

	err := ac.CreateAccount(db)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		help()
		os.Exit(2)
	}

	db, err := redqdb.NewSafeDB()
	if err != nil {
		log.Fatal(err)
	}

	switch args[0] {
	case "help":
		help()
	case "create":
		create(args[1:], db)
	default:
		help()
		os.Exit(2)
	}
}
