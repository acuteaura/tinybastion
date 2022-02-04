package oidc

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

var DefaultProvider = NewProvider()

var _ ProviderInterface = DefaultProvider

type ProviderInterface interface {
	VerifyToken(tokenString string, issuer string) (*jwt.Token, error)
}

func NewProvider() *Provider {
	return &Provider{
		discovery: NewDiscoveryClient(),
	}
}

type ClientConfig struct {
	Issuer   string
	ClientID string
}

type Provider struct {
	discovery *DiscoveryClient
}

func (p *Provider) VerifyToken(tokenString string, issuer string) (*jwt.Token, error) {
	claims := Claims{}
	return jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if err := claims.Valid(); err != nil {
			return nil, err
		}
		if !claims.VerifyIssuer(issuer, true) {
			return nil, errors.Errorf("iss is not allowed [have=%s,expected=%s]", claims.Issuer, issuer)
		}
		if !claims.VerifyTyp("ID", true) {
			return nil, errors.Errorf("typ is not allowed [have=%s,expected=%s]", claims.Type, "ID")
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		jwks, err := p.discovery.GetJWKs(claims.Issuer)
		if err != nil {
			return nil, err
		}
		keyIDRaw, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("key id missing from JWT header")
		}
		keyID, ok := keyIDRaw.(string)
		if !ok {
			return nil, errors.New("key id missing from JWT header")
		}
		key, ok := jwks.LookupKeyID(keyID)
		if !ok {
			return nil, errors.New("key id not on keychain")
		}

		var rawKey *rsa.PrivateKey
		err = key.Raw(&rawKey)
		if err != nil {
			return nil, err
		}
		return rawKey, nil
	})
}
