package oidc

import (
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
)

// make it possible to test cache exp without a 30 min test
var timeNow = time.Now

func NewOIDCCache() *OIDCCache {
	return &OIDCCache{
		responseCache: map[string]discoveryResponseCacheEntry{},
		jwkCache:      map[string]jwkCacheEntry{},
	}
}

type OIDCCache struct {
	responseCache   map[string]discoveryResponseCacheEntry
	jwkCache        map[string]jwkCacheEntry
	responseCacheMu sync.RWMutex
	jwkCacheMu      sync.RWMutex
}

type discoveryResponseCacheEntry struct {
	exp time.Time
	res *DiscoveryResponse
}

type jwkCacheEntry struct {
	exp time.Time
	set jwk.Set
}

func (dc *OIDCCache) StoreResponse(response DiscoveryResponse) {
	dce := discoveryResponseCacheEntry{
		exp: timeNow().Add(time.Minute * 30),
		res: &response,
	}
	dc.responseCacheMu.Lock()
	dc.responseCache[response.Issuer] = dce
	dc.responseCacheMu.Unlock()
}

func (dc *OIDCCache) GetResponse(issuer string) *DiscoveryResponse {
	dc.responseCacheMu.RLock()
	dce, ok := dc.responseCache[issuer]
	dc.responseCacheMu.RUnlock()
	if !ok {
		return nil
	}
	if timeNow().After(dce.exp) {
		return nil
	}
	return dce.res
}

func (dc *OIDCCache) StoreKeys(issuer string, set jwk.Set) {
	dce := jwkCacheEntry{
		exp: timeNow().Add(time.Minute * 30),
		set: set,
	}
	dc.jwkCacheMu.Lock()
	dc.jwkCache[issuer] = dce
	dc.jwkCacheMu.Unlock()
}

func (dc *OIDCCache) GetKeys(issuer string) jwk.Set {
	dc.jwkCacheMu.RLock()
	dce, ok := dc.jwkCache[issuer]
	dc.jwkCacheMu.RUnlock()
	if !ok {
		return nil
	}
	if timeNow().After(dce.exp) {
		return nil
	}
	return dce.set
}
