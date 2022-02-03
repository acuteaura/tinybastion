package tinybastion

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/acuteaura/tinybastion/internal/oidc"
	"io"
	"log"
	"net"
	"net/http"
)

type CreateTunnelRequest struct {
	PublicKey *MarshallableKey `json:"public_key"`
}

type CreateTunnelResponse struct {
	PeerConfig *MarshallablePeerConfig
}

func NewServer(ctx context.Context, listenPort int, oidcConfig *oidc.ClientConfig) *Server {
	s := &Server{}

	s.listener = &http.Server{
		Addr:    fmt.Sprintf(":%d", listenPort),
		Handler: s,
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	s.oidcProider = oidc.NewProvider()

	s.oidcConfig = oidcConfig

	go func() {
		err := s.listener.ListenAndServe()
		if err != nil {
			log.Default().Fatalf("http server error: %s", err)
		}
	}()

	return s
}

type Server struct {
	listener    *http.Server
	tb          *Bastion
	oidcProider oidc.ProviderInterface
	oidcConfig  *oidc.ClientConfig
}

func (s *Server) Destroy() error {
	return s.listener.Shutdown(context.Background())
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr, err := oidc.DetectJWT(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}

	_, err = s.oidcProider.VerifyToken(tokenStr, s.oidcConfig)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
	}

	req := CreateTunnelRequest{}
	err = json.Unmarshal(body, &req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.PublicKey == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	peerConfig, err := s.tb.AddPeer(req.PublicKey.K)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	mpc := &MarshallablePeerConfig{
		P:   *peerConfig,
		BSI: s.tb.ServerInfo(),
	}

	res := CreateTunnelResponse{mpc}

	data, err := json.Marshal(&res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}
