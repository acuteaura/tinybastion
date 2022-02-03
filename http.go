package tinybastion

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/acuteaura/tinybastion/internal/oidc"
	"github.com/google/uuid"
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

func NewServer(ctx context.Context, tb *Bastion, listenPort int, issuer string) *Server {
	s := &Server{}

	s.tb = tb

	s.listener = &http.Server{
		Addr:    fmt.Sprintf(":%d", listenPort),
		Handler: s,
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	s.oidcProider = oidc.NewProvider()

	s.oidcIssuer = issuer

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
	oidcIssuer  string
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
		httpError(w, http.StatusBadRequest, "bad content type")
		return
	}

	tokenStr, err := oidc.DetectJWT(r)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "no token supplied")
		return
	}

	verifiedToken, err := s.oidcProider.VerifyToken(tokenStr, s.oidcIssuer)
	if err != nil {
		httpError(w, http.StatusForbidden, fmt.Sprintf("bad token: %v", err))
		return
	}

	repositoryOwnerClaim, ok := verifiedToken.Get("repository_owner")
	if !ok {
		httpError(w, http.StatusForbidden, "repository_owner claim missing")
		return
	}

	repositoryOwner, ok := repositoryOwnerClaim.(string)
	if !ok {
		httpError(w, http.StatusInternalServerError, "claim conversion fault")
		return
	}

	// TODO: parameterize
	if repositoryOwner != "acuteaura" {
		httpError(w, http.StatusForbidden, fmt.Sprintf("unexpected github org: %s", repositoryOwner))
		return
	}

	req := CreateTunnelRequest{}
	err = json.Unmarshal(body, &req)

	if err != nil {
		httpError(w, http.StatusBadRequest, "cannot unmarshal json")
		return
	}

	if req.PublicKey == nil {
		httpError(w, http.StatusBadRequest, "empty public key")
		return
	}

	peerConfig, err := s.tb.AddPeer(req.PublicKey.K)
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Sprintf("addpeer failed: %s", err))
		return
	}

	mpc := &MarshallablePeerConfig{
		P:   *peerConfig,
		BSI: s.tb.ServerInfo(),
	}

	res := CreateTunnelResponse{mpc}

	data, err := json.Marshal(&res)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "cannot marshall response json")
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func httpError(w http.ResponseWriter, statusCode int, message string) {
	// generate a uuid so we can search for failures in logs
	eid := uuid.New()
	w.Header().Add("X-Error-ID", eid.String())
	w.WriteHeader(statusCode)
	w.Write([]byte(eid.String()))
	log.Default().Printf("[%s] http %d: %s", eid.String(), statusCode, message)
}
