package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
	redqdb "sinanmohd.com/redq/db"
)

type loginAPI struct {
	db       *redqdb.SafeDB
	validate *validator.Validate
	req      *RequestLogin
	resp     *ResponseLogin
}

type RequestLogin struct {
	Account *redqdb.Account `validate:"required"`
}

type ResponseLogin struct {
	Account *redqdb.Account
}

func newLogin(db *redqdb.SafeDB) *loginAPI {
	a := &loginAPI{}
	a.db = db
	a.validate = validator.New(validator.WithRequiredStructEnabled())

	return a
}

func (a *loginAPI) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	a.req = &RequestLogin{}
	a.resp = &ResponseLogin{}

	err := unmarshal(r.Body, a.req)
	if err == nil {
		err = a.validate.Struct(a.req)
	}
	if err != nil {
		handleError(err, rw, http.StatusUnprocessableEntity)
		return
	}

	err = a.req.Account.Login(a.db)
	if err != nil {
		handleError(err, rw, http.StatusUnauthorized)
		return
	}
	a.resp.Account = a.req.Account

	json, err := json.Marshal(a.resp)
	if err != nil {
		handleError(err, rw, http.StatusInternalServerError)
		return
	}

	rw.Write(json)
}
