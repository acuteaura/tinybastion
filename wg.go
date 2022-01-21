package tinybastion

import "github.com/vishvananda/netlink"

type wg struct {
	netlink.LinkAttrs
}

func (wglink *wg) Attrs() *netlink.LinkAttrs {
	return &wglink.LinkAttrs
}

func (wglink *wg) Type() string {
	return "wireguard"
}
