package oidc

import (
	"crypto/subtle"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	AuthorizedParty string `json:"azp,omitempty"`
	ExpiresAt       int64  `json:"exp,omitempty"`
	IssuedAt        int64  `json:"iat,omitempty"`
	Issuer          string `json:"iss,omitempty"`
	NotBefore       int64  `json:"nbf,omitempty"`
	Type            string `json:"typ,omitempty"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c Claims) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if c.VerifyExpiresAt(now, false) == false {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now, false) == false {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// Compares the azp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyTyp(cmp string, req bool) bool {
	return verifyTyp(c.Type, cmp, req)
}

// Compares the azp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyAuthorizedParty(cmp string, req bool) bool {
	return verifyAzp(c.AuthorizedParty, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(c.IssuedAt, cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyNotBefore(cmp int64, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
}

// ----- helpers

func verifyTyp(typ string, cmp string, required bool) bool {
	if typ == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(typ), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyAzp(azp string, cmp string, required bool) bool {
	if azp == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(azp), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}
