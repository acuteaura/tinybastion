package tinybastion

import (
	"github.com/acuteaura/tinybastion/internal/stabilizer"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"time"
)

type Bastion struct {
	Config *Config
	Client *wgctrl.Client

	peerCleanupStabilizer *stabilizer.IterativeStabilizer[wgtypes.Key]
}

func New(c Config) (*Bastion, error) {
	stab := stabilizer.NewIterative[wgtypes.Key](3)

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	bastion := &Bastion{Config: &c, Client: client, peerCleanupStabilizer: stab}
	err = bastion.init()
	if err != nil {
		return nil, err
	}
	return bastion, nil
}

func (b *Bastion) init() error {
	device, err := b.Client.Device(b.Config.DeviceName)
	if err != nil {
		return err
	}

	privkey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	device.PrivateKey = privkey

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

	newPeer := wgtypes.PeerConfig{
		PublicKey:                   key,
		PresharedKey:                &psk,
		Endpoint:                    nil,
		PersistentKeepaliveInterval: &persistentKeepalive,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  nil,
	}

	err = b.Client.ConfigureDevice(b.Config.DeviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{newPeer},
	})

	if err != nil {
		return nil, err
	}
	return &newPeer, nil
}
func (b *Bastion) CleanupPeers() error {
	device, err := b.Client.Device(b.Config.DeviceName)
	if err != nil {
		return err
	}

	badPeers := make(map[wgtypes.Key]struct{})
	for _, peer := range device.Peers {
		cutoffTimestamp := time.Now().Add(peer.PersistentKeepaliveInterval * -1)
		if peer.LastHandshakeTime.IsZero() || peer.LastHandshakeTime.Before(cutoffTimestamp) {
			badPeers[peer.PublicKey] = struct{}{}
		}
	}

	peersToRemove := make([]wgtypes.PeerConfig, 0, len(badPeers))
	for _, peerToRemove := range b.peerCleanupStabilizer.Iterate(badPeers) {
		peersToRemove = append(peersToRemove, wgtypes.PeerConfig{
			PublicKey: peerToRemove,
			Remove:    true,
		})
	}

	return nil
}
