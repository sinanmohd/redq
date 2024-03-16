package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func unmarshal(r io.Reader, v any) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, v)
	if err != nil {
		return err
	}

	return nil
}

func handleError(err error, rw http.ResponseWriter, status int) {
	log.Println(err)

	rw.WriteHeader(status)
	json := fmt.Sprintf(`{"Error": "%v"}`, http.StatusText(status))
	rw.Write([]byte(json))
}
