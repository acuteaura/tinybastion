package tinybastion

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"testing"
)

func TestMarshallableKey(t *testing.T) {
	key, err := wgtypes.ParseKey("0KH+kIcJtdVD8t00CaGi+iWi5A81YuRHicG06+XsTWo=")
	assert.NoError(t, err)

	mk := MarshallableKey{K: key}

	mkData, err := json.Marshal(&mk)
	assert.NoError(t, err)

	assert.Equal(t, "\"0KH+kIcJtdVD8t00CaGi+iWi5A81YuRHicG06+XsTWo=\"", string(mkData))

	mk2 := MarshallableKey{}
	err = json.Unmarshal(mkData, &mk2)
	assert.NoError(t, err)

	assert.Equal(t, mk, mk2)
}
