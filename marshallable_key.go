package tinybastion

import (
	"encoding/json"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type MarshallableKey struct {
	K wgtypes.Key
}

func (m *MarshallableKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.K.String())
}

func (m *MarshallableKey) UnmarshalJSON(bytes []byte) error {
	var keyStr string
	err := json.Unmarshal(bytes, &keyStr)
	if err != nil {
		return err
	}
	key, err := wgtypes.ParseKey(keyStr)
	if err != nil {
		return err
	}
	m.K = key
	return nil
}
