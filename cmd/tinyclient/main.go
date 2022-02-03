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

	config, err := json.Marshal(response.PeerConfig)
	if err != nil {
		log.Fatalf("Could not marshall peer config: %+v", config)
	}

	fmt.Print(string(config))
}
