package oidc

import "github.com/lestrrat-go/jwx/jwt"

var DefaultProvider = NewProvider()

var _ ProviderInterface = DefaultProvider

type ProviderInterface interface {
	VerifyToken(tokenString string, issuer string, options ...jwt.ParseOption) (jwt.Token, error)
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

func (p *Provider) VerifyToken(tokenString string, issuer string, options ...jwt.ParseOption) (jwt.Token, error) {
	keychain, err := p.discovery.GetJWKs(issuer)
	if err != nil {
		return nil, err
	}

	options = append(options,
		jwt.WithIssuer(issuer),
		jwt.WithKeySet(keychain),
		jwt.WithClaimValue("typ", "ID"),
	)

	return jwt.ParseString(
		tokenString,
		options...,
	)
}
