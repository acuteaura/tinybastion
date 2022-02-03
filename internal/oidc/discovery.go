package oidc

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/lestrrat-go/jwx/jwk"

	"log"

	"github.com/pkg/errors"
)

func NewDiscoveryClient() *DiscoveryClient {
	return &DiscoveryClient{
		Cache:      NewOIDCCache(),
		httpClient: http.DefaultClient,
	}
}

type DiscoveryClient struct {
	Cache      *OIDCCache
	httpClient *http.Client
}

func (dc *DiscoveryClient) GetDiscoveryRoot(issuer string) (*DiscoveryResponse, error) {
	if dr := dc.Cache.GetResponse(issuer); dr != nil {
		return dr, nil
	}
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse issuer as URL")
	}
	issuerUrl.Path = path.Join(issuerUrl.Path, ".well-known", "openid-configuration")
	res, err := dc.httpClient.Get(issuerUrl.String())
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve OIDC discovery configuration")
	}
	if res.StatusCode >= 400 {
		return nil, errors.Wrap(errors.Errorf("unexpected status code %d", res.StatusCode), "unable to retrieve OIDC discovery configuration")
	}
	discoveryResponseBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read OIDC discovery configuration from request body")
	}
	dr := &DiscoveryResponse{}
	err = json.Unmarshal(discoveryResponseBytes, dr)
	if err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal configuration from request body")
	}
	if dr.Issuer == "" {
		return nil, errors.New("bad response from OIDC discovery endpoint (missing issuer)")
	}
	if issuer != dr.Issuer {
		log.Default().Printf("discovery returned non-matching issuer, expected '%s', got '%s'", issuer, dr.Issuer)
	}
	dc.Cache.StoreResponse(*dr)
	return dr, nil
}

func (dc *DiscoveryClient) GetJWKs(issuer string) (jwk.Set, error) {
	cachedKeys := dc.Cache.GetKeys(issuer)
	if cachedKeys != nil {
		return cachedKeys, nil
	}
	dr, err := dc.GetDiscoveryRoot(issuer)
	if err != nil {
		return nil, err
	}

	keys, err := jwk.Fetch(context.TODO(), dr.JwksUri)
	if err != nil {
		return nil, err
	}
	dc.Cache.StoreKeys(issuer, keys)
	return keys, nil
}

type DiscoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}
