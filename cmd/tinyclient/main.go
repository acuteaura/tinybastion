package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/acuteaura/tinybastion"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log"
	"net/http"
	"os"
	"text/template"
)

func main() {
	// Get OIDC Token
	token, haveToken := os.LookupEnv("OIDC_TOKEN")
	if !haveToken {
		log.Default().Printf("Warning: proceeding without OIDC token (OIDC_TOKEN env was empty or not set).")
	}

	publicKey, ok := os.LookupEnv("PUBLIC_KEY")
	if !ok {
		log.Fatal("Cannot proceed without PUBLIC_KEY env set.")
	}
	wgKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		log.Fatalf("Could not parse public key: %+v", err)
	}

	privateKey, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		log.Fatal("Cannot proceed without PRIVATE_KEY env set.")
	}

	marshallableKey := tinybastion.MarshallableKey{K: wgKey}

	apiEndpoint, ok := os.LookupEnv("BASTION_API_ENDPOINT")
	if !ok {
		log.Fatal("Cannot proceed without BASTION_API_ENDPOINT env set.")
	}

	client := http.Client{}
	request := tinybastion.CreateTunnelRequest{
		PublicKey: &marshallableKey,
	}

	body, err := json.Marshal(request)
	if err != nil {
		log.Fatalf("Could not create request body: %+v", err)
	}

	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("Could not create new request: %+v", err)
	}

	req.Header.Add("Content-Type", "application/json")

	if haveToken {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10)
	req.WithContext(ctx)
	defer cancel()

	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Could not send POST request: %+v", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		log.Fatalf("Received a non 2xx response: %d", res.StatusCode)
	}

	var response tinybastion.CreateTunnelResponse
	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		log.Fatalf("Could not unmarshall response into CreateTunnelResponse: %+v", err)
	}

	log.Default().Printf("AllowedIPs:\n%+v\n", response.PeerConfig.P.AllowedIPs)

	var config struct {
		tinybastion.MarshallablePeerConfig

		ListenPort int
		PrivateKey string
		AllowedIPs []string
		DNS        string
	}
	config.P = response.PeerConfig.P
	config.BSI = response.PeerConfig.BSI
	config.ListenPort = 55555
	config.PrivateKey = privateKey
	config.AllowedIPs = []string{
		response.PeerConfig.BSI.GatewayIP,
		// TODO: Make this configurable
	}
	config.DNS = "1.1.1.1" // TODO: this too

	configTemplate, err := template.New("config").Parse(`
[Interface]
Address = {{index .P.AllowedIPs 0}}
ListenPort = {{.ListenPort}}
PrivateKey = {{.PrivateKey}}
PostUp = iptables -A FORWARD -i client -j ACCEPT; iptables -t nat -A POSTROUTING -o client -j MASQUERADE
PostDown = iptables -D FORWARD -i client -j ACCEPT; iptables -t nat -D POSTROUTING -o client -j MASQUERADE

[Peer]
# Bastion
PublicKey = {{.BSI.PublicKey}}
Endpoint = {{.BSI.EndpointHost}}:{{.BSI.EndpointPort}}
AllowedIPs = {{range .AllowedIPs}}{{.}}, {{end}}
PersistentKeepalive = {{.P.PersistentKeepaliveInterval}}
`)
	if err != nil {
		log.Fatalf("Could not create config template: %+v", err)
	}

	err = configTemplate.Execute(os.Stdout, config)
	if err != nil {
		log.Fatalf("Could not render WireGuard config: %+v", err)
	}
}
