package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
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
	type listener struct {
		name   string
		server *http.Server
		serve  func() error
	}
	listeners := []listener{{"API", api, api.ListenAndServe}, {"proxy", proxy, proxy.ListenAndServe}}
	var certConfig *certmagic.Config
	var acmeHost string
	certificateContext := ctx
	if host := os.Getenv("PROXY_ACME_HOST"); host != "" {
		if err := validateHost(host); err != nil {
			return fmt.Errorf("PROXY_ACME_HOST: %w", err)
		}
		if !strings.Contains(host, ".") {
			return fmt.Errorf("PROXY_ACME_HOST %q must be a fully qualified domain name", host)
		}
		cachePath := "/data/proxy-acme"
		if err := os.MkdirAll(cachePath, 0700); err != nil {
			return fmt.Errorf("create proxy certificate cache %q: %w", cachePath, err)
		}
		cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certConfig, nil
		}})
		var cancel context.CancelFunc
		certificateContext, cancel = context.WithCancel(ctx)
		defer func() {
			cancel()
			cache.Stop()
		}()
		certConfig = certmagic.New(cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: cachePath}})
		issuer := certmagic.NewACMEIssuer(certConfig, certmagic.ACMEIssuer{Agreed: true, DisableTLSALPNChallenge: true, AltHTTPPort: 8082})
		certConfig.Issuers = []certmagic.Issuer{issuer}
		acmeHost = host
		challenge := &http.Server{Addr: ":8082", Handler: issuer.HTTPChallengeHandler(http.NotFoundHandler()), ReadHeaderTimeout: 10 * time.Second}
		tlsProxy := &http.Server{
			Addr:              ":18443",
			Handler:           proxy.Handler,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if !strings.EqualFold(hello.ServerName, host) {
						return nil, fmt.Errorf("HTTPS proxy server name %q does not match %q", hello.ServerName, host)
					}
					return certConfig.GetCertificate(hello)
				},
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			},
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		}
		listeners = append(listeners, listener{"proxy ACME challenge", challenge, challenge.ListenAndServe}, listener{"HTTPS proxy", tlsProxy, func() error { return tlsProxy.ListenAndServeTLS("", "") }})
	}
	type result struct {
		name string
		err  error
	}
	done := make(chan result, len(listeners))
	for _, current := range listeners {
		go func() { done <- result{current.name, current.serve()} }()
	}
	shutdown := func() error {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var shutdownError error
		for _, current := range listeners {
			if err := current.server.Shutdown(shutdownContext); err != nil {
				shutdownError = errors.Join(shutdownError, fmt.Errorf("stop %s listener: %w", current.name, err))
			}
		}
		return shutdownError
	}
	if certConfig != nil {
		if err := certConfig.ManageAsync(certificateContext, []string{acmeHost}); err != nil {
			return errors.Join(fmt.Errorf("start certificate management for %q: %w", acmeHost, err), shutdown())
		}
	}
	select {
	case outcome := <-done:
		shutdownError := shutdown()
		if ctx.Err() != nil || errors.Is(outcome.err, http.ErrServerClosed) {
			return shutdownError
		}
		return errors.Join(fmt.Errorf("%s listener failed: %w", outcome.name, outcome.err), shutdownError)
	case <-ctx.Done():
		return shutdown()
	}
}
