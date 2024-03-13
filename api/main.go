package api

import (
	"fmt"
	"net/http"

	redqdb "sinanmohd.com/redq/db"
)

func Run(db *redqdb.SafeDB) {
	const prefix string = "POST /_redq/api"

	exampleApi := newExamplApiName(db)
	http.Handle(prefix+"/example", exampleApi)

	http.HandleFunc("GET /{$}", home)
	http.ListenAndServe(":8008", nil)
}

func home(rw http.ResponseWriter, r *http.Request) {
	const index string = `
		<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>🚨 redq</title>
			</head>
			<body>
				<center>
					<h1 style="font-size: 10em">
						redq is active
					</h1>
					<p style="font-weight: bold">
						we're soo back 🥳
					</p>
				</center>
			</body>
		</html>
	`

	fmt.Fprint(rw, index)
}
