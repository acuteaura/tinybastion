package oidc

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

func DetectJWT(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 {
			return "", errors.New("detected bearer token, but in invalid format")
		}
		return authHeaderParts[1], nil
	}
	return "", nil
}
