package tinybastion

import (
	"encoding/json"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type MarshallablePeerConfig struct {
	P   wgtypes.PeerConfig
	BSI BastionServerInfo
}

func (m *MarshallablePeerConfig) MarshalJSON() ([]byte, error) {
	out := struct {
		Endpoint                    string
		Gateway                     string
		PresharedKey                string
		PersistentKeepaliveInterval int
		PublicKey                   string
	}{
		fmt.Sprintf("%s:%d", m.BSI.EndpointHost, m.BSI.EndpointPort),
		m.BSI.GatewayIP,
		m.P.PresharedKey.String(),
		int(m.P.PersistentKeepaliveInterval.Seconds()),
		m.BSI.PublicKey,
	}
	return json.Marshal(&out)
}

func (m *MarshallablePeerConfig) UnmarshalJSON(bytes []byte) error {
	//TODO implement for client
	panic("implement me")
}
