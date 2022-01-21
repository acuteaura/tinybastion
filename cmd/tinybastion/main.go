package main

import (
	"github.com/acuteaura/tinybastion"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log"
	"os"
	"os/signal"
)

func main() {
	tb, err := tinybastion.New(tinybastion.Config{
		DeviceName:          "tinybastion",
		Port:                5555,
		PersistentKeepalive: 10,
		ExternalHostname:    "localhost",
		CIDR:                "10.99.0.1/24",
	})
	if err != nil {
		panic(err)
	}
	defer func() {
		err := tb.Destroy()
		if err != nil {
			log.Default().Printf("destroying interface failed, you may need to collect debris")
		}
	}()

	keyPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	keyPub := keyPriv.PublicKey()

	pconfig, err := tb.AddPeer(keyPub)
	if err != nil {
		panic(err)
	}

	log.Default().Printf("%v", pconfig)

	log.Default().Printf("%v", tb.ServerInfo())

	intChan := make(chan os.Signal)
	signal.Notify(intChan, os.Interrupt, os.Kill)

	<-intChan

	err = tb.CleanupPeers()
	if err != nil {
		panic(err)
	}
}
