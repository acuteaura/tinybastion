package tinybastion

import (
	"encoding/json"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"strconv"
	"strings"
	"time"
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
		AllowedIP                   string
	}{
		Endpoint:                    fmt.Sprintf("%s:%d", m.BSI.EndpointHost, m.BSI.EndpointPort),
		Gateway:                     m.BSI.GatewayIP,
		PresharedKey:                m.P.PresharedKey.String(),
		PersistentKeepaliveInterval: int(m.P.PersistentKeepaliveInterval.Seconds()),
		PublicKey:                   m.BSI.PublicKey,
		// FIXME: this is assuming we only have a single ip, which is assuming a lot..
		AllowedIP: m.P.AllowedIPs[0].String(),
	}
	return json.Marshal(&out)
}

func (m *MarshallablePeerConfig) UnmarshalJSON(bytes []byte) error {
	//TODO implement for client
	var raw struct {
		Endpoint                    string
		Gateway                     string
		PresharedKey                string
		PersistentKeepaliveInterval int
		PublicKey                   string
		AllowedIP                   string
	}

	err := json.Unmarshal(bytes, &raw)
	if err != nil {
		return err
	}

	hostAndPort := strings.Split(raw.Endpoint, ":")
	host := hostAndPort[0]
	port, err := strconv.ParseInt(hostAndPort[1], 10, 32)
	if err != nil {
		return fmt.Errorf("could not parse port number: %+v", err)
	}

	m.BSI = BastionServerInfo{
		EndpointHost: host,
		EndpointPort: int(port),
		GatewayIP:    raw.Gateway,
		PublicKey:    raw.PublicKey,
	}

	preSharedKey, err := wgtypes.ParseKey(raw.PresharedKey)
	if err != nil {
		return fmt.Errorf("could not parse pre shared key: %+v", err)
	}

	_, ipNet, err := net.ParseCIDR(raw.AllowedIP)
	if err != nil {
		return fmt.Errorf("could not parse allowed IP as CIDR: %+v", err)
	}

	persistentKeepaliveInterval := time.Second * time.Duration(raw.PersistentKeepaliveInterval)
	m.P = wgtypes.PeerConfig{
		PresharedKey:                &preSharedKey,
		PersistentKeepaliveInterval: &persistentKeepaliveInterval,
		AllowedIPs: []net.IPNet{
			*ipNet,
		},
	}

	return nil
}
