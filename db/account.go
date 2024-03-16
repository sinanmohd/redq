package db

import (
	"errors"
	"fmt"
	"log"
)

type Account struct {
	UserName string `validate:"required,alphanum,max=64"`
	Password string `json:",omitempty" validate:"required,min=10,max=128"`

	Info *Login
}

type Login struct {
	id                  uint
	Level               uint   `validate:"gte=0,lte=100"`
	FirstName, LastName string `validate:"required,alphanumunicode"`
	Bearer              *Bearer
}

func (ac *Account) CreateAccount(safe *SafeDB) error {
	const sqlStatement string = `
		INSERT INTO Accounts (
			id,
			UserName,
			Password,
			Level,
			FirstName,
			LastName
		)
		VALUES (NULL, ?, ?, ?, ?, ?);
	`

	err := safe.validate.Struct(ac)
	if err != nil {
		return err
	}

	safe.mu.Lock()
	defer safe.mu.Unlock()

	_, err = safe.db.Exec(
		sqlStatement,
		ac.UserName,
		ToBlake3(ac.Password),

		ac.Info.FirstName,
		ac.Info.LastName,
		ac.Info.Level,
	)

	return err
}

func (ac *Account) Login(safe *SafeDB) error {
	const sqlStatementQuery string = `
		SELECT id, Password, Level, FirstName, LastName
		FROM Accounts
		WHERE Accounts.UserName = ?
	`

	err := safe.validate.Struct(ac)
	fmt.Println(ac.Password, ac.UserName)
	if err != nil {
		log.Println(err)
		return err
	}

	ac.Info = &Login{}
	ac.Info.Bearer = &Bearer{}
	safe.mu.Lock()
	row := safe.db.QueryRow(sqlStatementQuery, ac.UserName)
	safe.mu.Unlock()

	var Password string
	err = row.Scan(
		&ac.Info.id,
		&Password,
		&ac.Info.FirstName,
		&ac.Info.LastName,
		&ac.Info.Level,
	)
	if err != nil {
		return err
	}
	if Password != ToBlake3(ac.Password) {
		return errors.New("Auth failed")
	}
	ac.Password = ""

	err = ac.Info.Bearer.Generate(safe, ac.Info)
	if err != nil {
		return err
	}

	return err
}

func (ac *Account) fromBearer(safe *SafeDB, b *Bearer) error {
	const sqlStatementAccount string = `
		SELECT UserName, Password, Level, FirstName, LastName
		FROM Accounts
		WHERE Accounts.id = ?
	`

	safe.mu.Lock()
	row := safe.db.QueryRow(sqlStatementAccount, b.accountId)
	safe.mu.Unlock()

	ac.Info = &Login{}
	ac.Info.id = b.accountId
	ac.Info.Bearer = b
	err := row.Scan(
		&ac.UserName,
		&ac.Password,

		&ac.Info.FirstName,
		&ac.Info.LastName,
		&ac.Info.Level,
	)
	if err != nil {
		return err
	}
	ac.Info.Bearer = b

	return err
}
