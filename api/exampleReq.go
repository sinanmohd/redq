package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	redqdb "sinanmohd.com/redq/db"
)

type examplApiName struct {
	db   *redqdb.SafeDB
	req  *RequestApiName
	resp *ResponseApiName
}

type RequestApiName struct {
	BearerToken string
}

type ResponseApiName struct {
	Bearer *redqdb.Bearer
}

func newExamplApiName(db *redqdb.SafeDB) *examplApiName {
	a := &examplApiName{}
	a.db = db

	return a
}

func (a *examplApiName) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	a.req = &RequestApiName{}
	a.resp = &ResponseApiName{}
	a.resp.Bearer = &redqdb.Bearer{}

	err := unmarshal(r.Body, a.req)
	fmt.Println(a.req)
	if err != nil {
		handleError(err, rw, http.StatusUnprocessableEntity)
		return
	}

	err = a.resp.Bearer.VerifyAndUpdate(a.db, a.req.BearerToken)
	if err != nil {
		handleError(err, rw, http.StatusUnauthorized)
		return
	}

	json, err := json.Marshal(a.resp)
	if err != nil {
		handleError(err, rw, http.StatusInternalServerError)
		return
	}

	rw.Write(json)
}
