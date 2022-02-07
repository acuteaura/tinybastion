package tinybastion

import (
	"log"
	"net"
	"time"

	"github.com/acuteaura/tinybastion/internal/stabilizer"
	"github.com/jonboulle/clockwork"
	"github.com/metal-stack/go-ipam"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var clock = clockwork.NewRealClock()

type Bastion struct {
	Config *Config
	Client *wgctrl.Client

	gatewayIP             *ipam.IP
	ipam                  ipam.Ipamer
	peerCleanupStabilizer *stabilizer.IterativeStabilizer[wgtypes.Key]
	link                  netlink.Link
	publicKey             wgtypes.Key
}

type BastionServerInfo struct {
	EndpointHost string
	EndpointPort int
	GatewayIP    string
	PublicKey    string
}

func New(c Config) (*Bastion, error) {
	stab := stabilizer.NewIterative[wgtypes.Key](3)
	ipamer := ipam.New()
	_, err := ipamer.NewPrefix(c.CIDR)
	if err != nil {
		return nil, err
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	bastion := &Bastion{Config: &c, Client: client, peerCleanupStabilizer: stab, ipam: ipamer}
	err = bastion.init()
	if err != nil {
		return nil, err
	}
	return bastion, nil
}

func (b *Bastion) init() error {
	// check if we need to re-create the interface
	// do not attempt to reuse an interface, since we'd have to reset WG state AND addrs
	link, err := netlink.LinkByName(b.Config.DeviceName)
	if err != nil {
		_, ok := err.(netlink.LinkNotFoundError)
		if !ok {
			return err
		}
	} else {
		log.Default().Printf("link %s found, re-creating", b.Config.DeviceName)
		err = netlink.LinkDel(link)
		if err != nil {
			return errors.Wrap(err, "unable to delete link")
		}
	}

	wgLinkAttr := netlink.NewLinkAttrs()
	wgLinkAttr.Name = b.Config.DeviceName

	wgLink := &wg{
		LinkAttrs: wgLinkAttr,
	}

	err = netlink.LinkAdd(wgLink)
	if err != nil {
		return errors.Wrap(err, "unable to create link")
	}

	// reaquire the link to get the index
	b.link, err = netlink.LinkByName(b.Config.DeviceName)
	if err != nil {
		return err
	}

	ip, err := b.ipam.AcquireIP(b.Config.CIDR)
	if err != nil {
		return err
	}

	err = netlink.AddrAdd(wgLink, &netlink.Addr{IPNet: &net.IPNet{
		IP:   ip.IP.IPAddr().IP,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}})
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(b.link)
	if err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(b.Config.CIDR)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		Dst:       ipnet,
		LinkIndex: b.link.Attrs().Index,
	}
	err = netlink.RouteAdd(route)
	if err != nil {
		return err
	}

	b.gatewayIP = ip

	_, err = b.Client.Device(b.Config.DeviceName)
	if err != nil {
		return err
	}

	privkey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	b.publicKey = privkey.PublicKey()

	port := b.Config.Port

	err = b.Client.ConfigureDevice(b.Config.DeviceName, wgtypes.Config{
		PrivateKey: &privkey,
		ListenPort: &port,

		// make sure we start from a clean slate
		ReplacePeers: true,
	})
	if err != nil {
		return err
	}

	return nil
}

func (b *Bastion) AddPeer(key wgtypes.Key) (*wgtypes.PeerConfig, error) {
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return nil, err
	}

	persistentKeepalive := time.Duration(b.Config.PersistentKeepalive) * time.Second

	ip, err := b.ipam.AcquireIP(b.Config.CIDR)
	if err != nil {
		return nil, err
	}

	newPeer := wgtypes.PeerConfig{
		PublicKey:                   key,
		PresharedKey:                &psk,
		Endpoint:                    nil,
		PersistentKeepaliveInterval: &persistentKeepalive,
		ReplaceAllowedIPs:           true,

		AllowedIPs: []net.IPNet{
			{IP: ip.IP.IPAddr().IP, Mask: net.IPv4Mask(255, 255, 255, 255)},
		},
	}

	err = b.Client.ConfigureDevice(b.Config.DeviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{newPeer},
	})

	if err != nil {
		return nil, err
	}

	log.Default().Printf("added new peer %s@%s", newPeer.PublicKey.PublicKey(), newPeer.AllowedIPs[0].String())

	return &newPeer, nil
}

func (b *Bastion) CleanupPeers() error {
	device, err := b.Client.Device(b.Config.DeviceName)
	if err != nil {
		return err
	}

	badPeers := make(map[wgtypes.Key]struct{})
	for _, peer := range device.Peers {
		cutoffTimestamp := clock.Now().Add(peer.PersistentKeepaliveInterval * -1)
		if peer.LastHandshakeTime.IsZero() || peer.LastHandshakeTime.Before(cutoffTimestamp) {
			badPeers[peer.PublicKey] = struct{}{}
		}
	}

	log.Default().Printf("found %d candidates for deletion", len(badPeers))

	peersToRemove := make([]wgtypes.PeerConfig, 0, len(badPeers))
	for _, peerToRemove := range b.peerCleanupStabilizer.Iterate(badPeers) {
		peersToRemove = append(peersToRemove, wgtypes.PeerConfig{
			PublicKey: peerToRemove,
			Remove:    true,
		})
	}

	log.Default().Printf("deleting peers: %v", peersToRemove)

	err = b.Client.ConfigureDevice(b.Config.DeviceName, wgtypes.Config{Peers: peersToRemove})
	if err != nil {
		return err
	}

	return nil
}

func (b *Bastion) Destroy() error {
	return netlink.LinkDel(b.link)
}

func (b *Bastion) ServerInfo() BastionServerInfo {
	return BastionServerInfo{
		EndpointHost: b.Config.ExternalHostname,
		EndpointPort: b.Config.Port,
		GatewayIP:    b.gatewayIP.IP.String(),
		PublicKey:    b.publicKey.String(),
	}
}
