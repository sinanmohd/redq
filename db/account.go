package db

import "errors"

type Account struct {
	UserName string
	PassHash string

	Info *Login
}

type Login struct {
	id                  uint
	Level               uint
	FirstName, LastName string
	Bearer              *Bearer
}

func (ac *Account) CreateAccount(safe *SafeDB) error {
	const sqlStatement string = `
		INSERT INTO Accounts (
			id,
			UserName,
			PassHash,
			Level,
			FirstName,
			LastName
		)
		VALUES (NULL, ?, ?, ?, ?, ?);
	`

	safe.mu.Lock()
	defer safe.mu.Unlock()

	_, err := safe.db.Exec(
		sqlStatement,
		ac.UserName,
		ToBlake3(ac.PassHash),

		ac.Info.FirstName,
		ac.Info.LastName,
		ac.Info.Level,
	)

	return err
}

func (ac *Account) Login(safe *SafeDB) error {
	const sqlStatementQuery string = `
		SELECT id, PassHash, Level, FirstName, LastName
		FROM Accounts
		WHERE Accounts.UserName = ?
	`

	ac.Info = &Login{}
	ac.Info.Bearer = &Bearer{}
	safe.mu.Lock()
	row := safe.db.QueryRow(sqlStatementQuery, ac.UserName)
	safe.mu.Unlock()

	var PassHash string
	err := row.Scan(
		&ac.Info.id,
		&PassHash,
		&ac.Info.FirstName,
		&ac.Info.LastName,
		&ac.Info.Level,
	)
	if err != nil {
		return err
	}
	if PassHash != ac.PassHash {
		return errors.New("Auth failed")
	}

	err = ac.Info.Bearer.Generate(safe, ac.Info)
	if err != nil {
		return err
	}

	return err
}

func (ac *Account) fromBearer(safe *SafeDB, b *Bearer) error {
	const sqlStatementAccount string = `
		SELECT UserName, PassHash, Level, FirstName, LastName
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
		&ac.PassHash,

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
