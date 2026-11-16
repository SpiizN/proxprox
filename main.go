package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mode := envOr("APP_MODE", "server")
	var err error
	switch mode {
	case "server":
		err = runServer(ctx)
	case "gateway":
		err = runGateway(ctx, os.Getenv("GATEWAY_TOKEN"), os.Getenv("VPN_DNS"), envOr("OPENVPN_CONFIG", "/vpn/client.ovpn"), envOr("GATEWAY_LISTEN", ":8081"))
	default:
		err = fmt.Errorf("unknown APP_MODE %q", mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func runServer(ctx context.Context) error {
	apiToken := os.Getenv("API_TOKEN")
	proxyToken := os.Getenv("PROXY_TOKEN")
	gatewayToken := os.Getenv("GATEWAY_TOKEN")
	for name, value := range map[string]string{"API_TOKEN": apiToken, "PROXY_TOKEN": proxyToken, "GATEWAY_TOKEN": gatewayToken} {
		if len(value) < 16 || strings.HasPrefix(value, "replace-with-") {
			return fmt.Errorf("%s must be a non-placeholder secret of at least 16 characters", name)
		}
	}
	store, err := newStore(envOr("CONFIG_PATH", "/data/config.json"))
	if err != nil {
		return err
	}
	apiAddress := envOr("API_LISTEN", ":8000")
	proxyAddress := envOr("PROXY_LISTEN", ":8080")
	api := &http.Server{Addr: apiAddress, Handler: &API{store: store, token: apiToken}, ReadHeaderTimeout: 10 * time.Second}
	proxy := &http.Server{Addr: proxyAddress, Handler: &Proxy{store: store, token: proxyToken, gatewayToken: gatewayToken}, ReadHeaderTimeout: 10 * time.Second}
	type result struct {
		name string
		err  error
	}
	done := make(chan result, 2)
	go func() { done <- result{"API", api.ListenAndServe()} }()
	go func() { done <- result{"proxy", proxy.ListenAndServe()} }()
	select {
	case outcome := <-done:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = api.Shutdown(shutdownContext)
		_ = proxy.Shutdown(shutdownContext)
		if ctx.Err() != nil || errors.Is(outcome.err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("%s listener failed: %w", outcome.name, outcome.err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		apiError := api.Shutdown(shutdownContext)
		proxyError := proxy.Shutdown(shutdownContext)
		if apiError != nil {
			return fmt.Errorf("stop API listener: %w", apiError)
		}
		if proxyError != nil {
			return fmt.Errorf("stop proxy listener: %w", proxyError)
		}
		return nil
	}
}
