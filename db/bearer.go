package db

import (
	"errors"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Bearer struct {
	id, accountId uint
	Token         string
	ValidUpTo     time.Time
}

func (b *Bearer) FromToken(safe *SafeDB, Token string) error {
	const sqlStatementBearer string = `
		SELECT id, ValidUpTo, accountId
		FROM Bearer
		WHERE Bearer.Token = ?
	`

	b.Token = Token
	var ValidUpToString string
	safe.mu.Lock()
	row := safe.db.QueryRow(sqlStatementBearer, Token)
	safe.mu.Unlock()

	err := row.Scan(
		&b.id,
		&ValidUpToString,
		&b.accountId,
	)
	if err != nil {
		return err
	}

	layout := "2006-01-02 15:04:05.999999999-07:00"
	b.ValidUpTo, err = time.Parse(layout, ValidUpToString)
	if err != nil {
		return err
	}

	timeNow := time.Now()
	if timeNow.After(b.ValidUpTo) {
		return errors.New("Outdated Bearer Token")
	}

	return err
}

func (b *Bearer) Update(safe *SafeDB) error {
	const sqlStatementBearer string = `
		UPDATE Bearer
		SET ValidUpTo = ?
		WHERE id = ?
	`

	validUpTo := time.Now().Add(time.Hour * 24)
	safe.mu.Lock()
	_, err := safe.db.Exec(sqlStatementBearer, validUpTo, b.id)
	safe.mu.Unlock()
	if err != nil {
		return err
	}
	b.ValidUpTo = validUpTo

	return nil
}

func (b *Bearer) VerifyAndUpdate(safe *SafeDB, token string) error {
	err := b.FromToken(safe, token)
	if err != nil {
		return err
	}

	err = b.Update(safe)
	if err != nil {
		return err
	}

	return nil
}

func (b *Bearer) Generate(safe *SafeDB, lg *Login) error {
	const sqlGenBearer string = `
		INSERT INTO Bearer (
			id,
			Token,
			ValidUpTo,
			accountId
		)
		VALUES (NULL, ?, ?, ?);
	`

	Token, err := GenRandomString(128)
	if err != nil {
		return err
	}

	timeNow := time.Now()
	ValidUpTo := timeNow.Add(time.Hour * 24)
	safe.mu.Lock()
	res, err := safe.db.Exec(
		sqlGenBearer,
		Token,
		ValidUpTo,
		lg.id,
	)
	safe.mu.Unlock()
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}

	b.id = uint(id)
	b.accountId = lg.id
	b.Token = Token
	b.ValidUpTo = ValidUpTo
	lg.Bearer = b

	return err
}
