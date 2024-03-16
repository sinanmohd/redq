package api

import (
	"fmt"
	"log"
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
	Error  string `json:"error,omitempty"`
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
	if err != nil {
		log.Println(err)
		return
	}

	err = a.resp.Bearer.VerifyAndUpdate(a.db, a.req.BearerToken)
	if err != nil {
		log.Println(err)
		a.resp.Error = err.Error()
		return
	}

	json, err := marshal(a.resp)
	if err != nil {
		log.Println(err)
		a.resp.Error = err.Error()
		return
	}

	fmt.Fprintf(rw, json)
}
