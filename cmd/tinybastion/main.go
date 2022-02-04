package main

import (
	"context"
	"flag"
	"github.com/acuteaura/tinybastion"
	"log"
	"os"
	"os/signal"
	"time"
)

func main() {
	var deviceName, externalHostname, cidr, oidcIssuer string
	var wgPort, httpPort, persistentKeepalive int
	var help bool

	flag.StringVar(&deviceName, "device-name", "tinybastion", "wireguard device name (will be created/deleted)")
	flag.StringVar(&externalHostname, "external-hostname", "localhost", "hostname to advertise in peer config for this instance")
	flag.StringVar(&cidr, "cidr", "10.0.0.0/24", "network in CIDR format to allocate IPs from (including gateway)")
	flag.IntVar(&wgPort, "wg-port", 5555, "port for wireguard")
	flag.IntVar(&httpPort, "http-port", 8080, "port for http")
	flag.IntVar(&persistentKeepalive, "persistent-keepalive", 30, "persistentkeepalive value to use for WG")
	flag.BoolVar(&help, "help", false, "print usage")

	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	tb, err := tinybastion.New(tinybastion.Config{
		DeviceName:          deviceName,
		Port:                wgPort,
		PersistentKeepalive: persistentKeepalive,
		ExternalHostname:    externalHostname,
		CIDR:                cidr,
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

	tinybastion.NewServer(context.TODO(), httpPort, oidcIssuer)

	go func(ctx context.Context) {
		t := time.Tick(time.Minute)
		select {
		case <-t:
			err = tb.CleanupPeers()
			if err != nil {
				panic(err)
			}
		case <-ctx.Done():
			return
		}
	}(context.TODO())

	intChan := make(chan os.Signal)
	signal.Notify(intChan, os.Interrupt, os.Kill)

	<-intChan
}
