package main

import (
	"context"
	"github.com/acuteaura/tinybastion"
	"github.com/acuteaura/tinybastion/internal/oidc"
	"log"
	"os"
	"os/signal"
	"time"
)

func main() {
	tb, err := tinybastion.New(tinybastion.Config{
		DeviceName:          "tinybastion",
		Port:                5555,
		PersistentKeepalive: 10,
		ExternalHostname:    "localhost",
		CIDR:                "10.99.0.0/24",
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

	tinybastion.NewServer(context.TODO(), 8080, &oidc.ClientConfig{
		Issuer:   "mock",
		ClientID: "mock",
	})

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
