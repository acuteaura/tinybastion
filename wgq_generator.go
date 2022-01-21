package tinybastion

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

func GenerateWireguardConfig(serverInfo *BastionServerInfo, peerConfig wgtypes.PeerConfig) string {
	tmpl := `[Interface]
Address = {{ .ServerInfo.
SaveConfig = true
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820


[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.192.122.3/32, 10.192.124.1/24`
	template.
}
