package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		connection.Close()
		writeError(w, http.StatusInternalServerError, "HTTP server does not support CONNECT tunneling")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		connection.Close()
		log.Printf("VPN gateway hijack %s: %v", r.Host, err)
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		connection.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		client.Close()
		connection.Close()
		return
	}
	go func() {
		copyTunnel(connection, buffered.Reader, r.Host)
	}()
	copyTunnel(client, connection, r.Host)
	client.Close()
	connection.Close()
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
	if len(token) < 16 || strings.HasPrefix(token, "replace-with-") {
		return fmt.Errorf("GATEWAY_TOKEN must be a non-placeholder secret of at least 16 characters")
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
	select {
	case err := <-processDone:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("OpenVPN profile %q exited: %w", configPath, err)
		}
		return fmt.Errorf("OpenVPN profile %q exited unexpectedly", configPath)
	case err := <-serverDone:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		<-processDone
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("VPN gateway HTTP server on %s: %w", address, err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		<-processDone
		return nil
	}
}
