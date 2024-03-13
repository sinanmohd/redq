package db

import (
	"encoding/base64"
	"lukechampine.com/blake3"
	"math/rand"
)

func ToBlake3(pass string) string {
	hash := blake3.Sum512([]byte(pass))
	hash64b := base64.StdEncoding.EncodeToString(hash[:])

	return "blake3-" + hash64b
}

func GenRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b)[:n], nil
}
