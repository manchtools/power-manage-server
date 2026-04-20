package main

import (
	"fmt"
	"net/http"
)

// buildWebMux wires the gateway's terminal-WebSocket HTTP handlers.
//
// Two paths route to the same bridge handler:
//
//   - /terminal               — used by single-gateway deployments
//     where the public URL is wss://<host>/terminal (the Traefik
//     router routes by Host only).
//   - /gw/<gatewayID>/terminal — used by multi-gateway deployments
//     where Traefik's per-replica router rule is
//     `Host(<ttyHost>) && PathPrefix(/gw/<id>)`. Traefik does NOT
//     strip the prefix when forwarding, so the gateway sees the
//     full path. Registering the prefixed route here is what lets
//     the same binary work under either routing scheme.
//
// When gatewayID is empty the prefixed route is omitted — there's
// no stable ID to key it on, and single-gateway setups don't need it.
func buildWebMux(gatewayID string, bridgeHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/terminal", bridgeHandler)
	if gatewayID != "" {
		mux.Handle(fmt.Sprintf("/gw/%s/terminal", gatewayID), bridgeHandler)
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}
