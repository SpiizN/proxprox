package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const soBindToDevice = 25 // Linux SO_BINDTODEVICE keeps gateway traffic on tun0.

type Gateway struct {
	token string
	dnsIP string
}

func (gateway *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		interfaceInfo, err := net.InterfaceByName("tun0")
		if err != nil || interfaceInfo.Flags&net.FlagUp == 0 {
			writeError(w, http.StatusServiceUnavailable, "VPN tunnel tun0 is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	username, password, ok := basicCredentials(r.Header.Get("Proxy-Authorization"))
	if !ok || username != "gateway" || !secureEqual(password, gateway.token) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxprox-vpn"`)
		writeError(w, http.StatusProxyAuthRequired, "missing or invalid gateway credentials")
		return
	}
	if r.Method != http.MethodConnect {
		methodNotAllowed(w, "CONNECT")
		return
	}
	if err := validateAddress(r.Host); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid CONNECT target %q: %v", r.Host, err))
		return
	}
	interfaceInfo, err := net.InterfaceByName("tun0")
	if err != nil || interfaceInfo.Flags&net.FlagUp == 0 {
		writeError(w, http.StatusServiceUnavailable, "VPN tunnel tun0 is unavailable")
		return
	}
	connection, err := gateway.dial(r.Context(), r.Host)
	if err != nil {
		log.Printf("VPN gateway dial %s: %v", r.Host, err)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("dial %s through VPN: %v", r.Host, err))
		return
	}
	serveTunnel(w, connection, r.Host)
}

func (gateway *Gateway) dial(ctx context.Context, address string) (net.Conn, error) {
	boundDialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: bindTun0}
	if gateway.dnsIP != "" {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return boundDialer.DialContext(ctx, network, net.JoinHostPort(gateway.dnsIP, "53"))
		}}
		boundDialer.Resolver = resolver
	}
	connection, err := boundDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("VPN tunnel target %s: %w", address, err)
	}
	return connection, nil
}

func bindTun0(_, _ string, raw syscall.RawConn) error {
	var socketError error
	if err := raw.Control(func(fd uintptr) {
		socketError = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, soBindToDevice, "tun0")
	}); err != nil {
		return err
	}
	return socketError
}

func runGateway(ctx context.Context, token, dnsIP, configPath, address string) error {
	if dnsIP != "" && net.ParseIP(dnsIP) == nil {
		return fmt.Errorf("VPN_DNS must be an IP address, got %q", dnsIP)
	}
	profilePath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve OpenVPN profile %q: %w", configPath, err)
	}
	profile, err := os.Open(profilePath)
	if err != nil {
		return fmt.Errorf("open OpenVPN profile %q: %w", configPath, err)
	}
	profileInfo, statError := profile.Stat()
	closeError := profile.Close()
	if statError != nil {
		return fmt.Errorf("inspect OpenVPN profile %q: %w", configPath, statError)
	}
	if closeError != nil {
		return fmt.Errorf("close OpenVPN profile %q: %w", configPath, closeError)
	}
	if !profileInfo.Mode().IsRegular() {
		return fmt.Errorf("OpenVPN profile %q must be a regular file", configPath)
	}
	if err := validateSecret("GATEWAY_TOKEN", token); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "openvpn", "--cd", filepath.Dir(profilePath), "--config", profilePath, "--dev", "tun0", "--auth-nocache")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start OpenVPN profile %q: %w", configPath, err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	server := &http.Server{Addr: address, Handler: &Gateway{token: token, dnsIP: dnsIP}, ReadHeaderTimeout: 10 * time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ListenAndServe() }()
	shutdown := func() error {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("stop VPN gateway HTTP server on %s: %w", address, err)
		}
		return nil
	}
	select {
	case err := <-processDone:
		shutdownError := shutdown()
		if ctx.Err() != nil {
			return shutdownError
		}
		if err != nil {
			return errors.Join(fmt.Errorf("OpenVPN profile %q exited: %w", configPath, err), shutdownError)
		}
		return errors.Join(fmt.Errorf("OpenVPN profile %q exited unexpectedly", configPath), shutdownError)
	case err := <-serverDone:
		killError := command.Process.Kill()
		<-processDone
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(killError, os.ErrProcessDone) {
			killError = nil
		}
		if killError != nil {
			killError = fmt.Errorf("stop OpenVPN profile %q: %w", configPath, killError)
		}
		return errors.Join(fmt.Errorf("VPN gateway HTTP server on %s: %w", address, err), killError)
	case <-ctx.Done():
		shutdownError := shutdown()
		<-processDone
		return shutdownError
	}
}
