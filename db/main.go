package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type SafeDB struct {
	mu sync.Mutex

	path string
	db   *sql.DB
}

func (safe *SafeDB) setupPath() error {
	const path string = "/var/lib/redq/"
	const name string = "redq.sqlite3"

	err := os.MkdirAll(path, os.ModeDir)
	if err != nil {
		return err
	}

	safe.path = filepath.Join(path, name)
	return nil
}

func NewSafeDB() (*SafeDB, error) {
	const create string = `
		CREATE TABLE IF NOT EXISTS Accounts(
			id        INTEGER PRIMARY KEY,
			Email     CHAR(64)	NOT NULL UNIQUE,
			PassHash  CHAR(128)	NOT NULL,

			Level     INTEGER	NOT NULL,
			FirstName CHAR(32)	NOT NULL,
			LastName  CHAR(32)	NOT NULL
		);

		CREATE TABLE IF NOT EXISTS Bearer(
			id	  INTEGER PRIMARY KEY,
			Token     CHAR(128)	NOT NULL UNIQUE,
			ValidUpTo TIME		NOT NULL,
			accountId INTEGER	NOT NULL,

			FOREIGN KEY (accountId)
			REFERENCES Accounts (id)
		);
	`
	safe := &SafeDB{}
	err := safe.setupPath()
	if err != nil {
		return nil, err
	}

	safe.mu.Lock()
	defer safe.mu.Unlock()

	safe.db, err = sql.Open("sqlite3", safe.path)
	if err != nil {
		return nil, err
	}

	_, err = safe.db.Exec(create)
	if err != nil {
		return nil, err
	}

	return safe, nil
}
