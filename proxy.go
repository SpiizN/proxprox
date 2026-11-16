package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Proxy struct {
	store        *Store
	token        string
	gatewayToken string
}

func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, ok := basicCredentials(r.Header.Get("Proxy-Authorization"))
	if !ok || username != "proxy" || !secureEqual(password, proxy.token) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxprox"`)
		writeError(w, http.StatusProxyAuthRequired, "missing or invalid proxy credentials")
		return
	}
	if r.Method == http.MethodConnect {
		proxy.connect(w, r)
		return
	}
	proxy.forwardHTTP(w, r)
}

func basicCredentials(header string) (string, string, bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	return username, password, ok
}

func (proxy *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil || validateAddress(r.Host) != nil || validateHost(strings.TrimSuffix(strings.ToLower(host), ".")) != nil {
		writeError(w, http.StatusBadRequest, "CONNECT target must be a valid host:port")
		return
	}
	state := proxy.store.snapshot()
	decision := state.decide(host)
	target, err := proxy.dialRoute(r.Context(), state, decision, r.Host)
	if err != nil {
		log.Printf("CONNECT %s via %s failed: %v", r.Host, decision.Route, err)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("connect to %s via %s: %v", r.Host, decision.Route, err))
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		writeError(w, http.StatusInternalServerError, "HTTP server does not support CONNECT tunneling")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		target.Close()
		log.Printf("hijack CONNECT %s: %v", r.Host, err)
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		target.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		client.Close()
		target.Close()
		return
	}
	go func() {
		copyTunnel(target, buffered.Reader, r.Host)
	}()
	copyTunnel(client, target, r.Host)
	client.Close()
	target.Close()
}

func copyTunnel(destination net.Conn, source io.Reader, target string) {
	if _, err := io.Copy(destination, source); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("tunnel copy for %s: %v", target, err)
	}
	if err := closeWrite(destination); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("tunnel half-close for %s: %v", target, err)
	}
}

func closeWrite(conn net.Conn) error {
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}

func (proxy *Proxy) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		writeError(w, http.StatusBadRequest, "proxy requests must use an absolute http URL without URL credentials")
		return
	}
	host := strings.TrimSuffix(strings.ToLower(r.URL.Hostname()), ".")
	if err := validateHost(host); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid target host: %v", err))
		return
	}
	state := proxy.store.snapshot()
	decision := state.decide(host)
	transport, err := proxy.transportFor(state, decision)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("prepare route for %s: %v", host, err))
		return
	}
	defer transport.CloseIdleConnections()
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Header = r.Header.Clone()
	upgrade := request.Header.Get("Upgrade")
	if upgrade != "" && !headerHasToken(request.Header.Get("Connection"), "upgrade") {
		writeError(w, http.StatusBadRequest, "Upgrade requires Connection: Upgrade")
		return
	}
	removeHopHeaders(request.Header)
	if upgrade != "" {
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", upgrade)
	}
	request.Header.Del("Proxy-Authorization")
	response, err := transport.RoundTrip(request)
	if err != nil {
		log.Printf("HTTP %s via %s failed: %v", host, decision.Route, err)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("forward request to %s via %s: %v", host, decision.Route, err))
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		proxy.forwardUpgrade(w, r, response, upgrade)
		return
	}
	removeHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		log.Printf("copy HTTP response from %s: %v", host, err)
	}
}

func headerHasToken(value, token string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return true
		}
	}
	return false
}

func (proxy *Proxy) forwardUpgrade(w http.ResponseWriter, r *http.Request, response *http.Response, requested string) {
	upstream, ok := response.Body.(io.ReadWriteCloser)
	if requested == "" || !ok || !strings.EqualFold(requested, response.Header.Get("Upgrade")) {
		writeError(w, http.StatusBadGateway, "upstream returned an invalid protocol upgrade")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "HTTP server does not support protocol upgrades")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Printf("hijack upgrade for %s: %v", r.URL.Host, err)
		return
	}
	headers := response.Header.Clone()
	removeHopHeaders(headers)
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", requested)
	if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		client.Close()
		return
	}
	for key, values := range headers {
		for _, value := range values {
			if _, err := fmt.Fprintf(buffered, "%s: %s\r\n", key, value); err != nil {
				client.Close()
				return
			}
		}
	}
	if _, err := buffered.WriteString("\r\n"); err != nil {
		client.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		client.Close()
		return
	}
	go func() {
		if _, err := io.Copy(upstream, buffered.Reader); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("upgrade client-to-upstream copy for %s: %v", r.URL.Host, err)
		}
		if halfCloser, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()
	copyTunnel(client, upstream, r.URL.Host)
	client.Close()
}

func removeHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func (proxy *Proxy) transportFor(state State, decision Decision) (*http.Transport, error) {
	transport := &http.Transport{
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if decision.Upstream != "" {
		upstream, ok := state.getUpstream(decision.Upstream)
		if !ok {
			return nil, fmt.Errorf("upstream %q is missing", decision.Upstream)
		}
		u, err := parseUpstreamURL(upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", upstream.Name, err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if decision.VPN == "" {
			return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
		}
		vpn, ok := state.getVPN(decision.VPN)
		if !ok {
			return nil, fmt.Errorf("VPN %q is missing", decision.VPN)
		}
		return proxy.dialGateway(ctx, vpn, address)
	}
	return transport, nil
}

func (proxy *Proxy) dialRoute(ctx context.Context, state State, decision Decision, target string) (net.Conn, error) {
	var upstream *url.URL
	if decision.Upstream != "" {
		item, ok := state.getUpstream(decision.Upstream)
		if !ok {
			return nil, fmt.Errorf("upstream %q is missing", decision.Upstream)
		}
		var err error
		upstream, err = parseUpstreamURL(item.URL)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", item.Name, err)
		}
	}
	endpoint := target
	if upstream != nil {
		endpoint = upstream.Host
	}
	var conn net.Conn
	var err error
	if decision.VPN == "" {
		conn, err = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", endpoint)
	} else {
		vpn, ok := state.getVPN(decision.VPN)
		if !ok {
			return nil, fmt.Errorf("VPN %q is missing", decision.VPN)
		}
		conn, err = proxy.dialGateway(ctx, vpn, endpoint)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", endpoint, err)
	}
	if upstream == nil {
		return conn, nil
	}
	if upstream.Scheme == "https" {
		secured := tls.Client(conn, &tls.Config{ServerName: upstream.Hostname(), MinVersion: tls.VersionTLS12})
		if err := secured.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with upstream %s: %w", upstream.Host, err)
		}
		conn = secured
	}
	conn, err = writeConnect(conn, target, upstream.User)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT through upstream %s to %s: %w", upstream.Host, target, err)
	}
	return conn, nil
}

func (proxy *Proxy) dialGateway(ctx context.Context, vpn VPN, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", vpn.Gateway)
	if err != nil {
		return nil, fmt.Errorf("dial VPN gateway %s: %w", vpn.Name, err)
	}
	auth := url.UserPassword("gateway", proxy.gatewayToken)
	conn, err = writeConnect(conn, target, auth)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("VPN gateway %s CONNECT to %s: %w", vpn.Name, target, err)
	}
	return conn, nil
}

func writeConnect(conn net.Conn, target string, credentials *url.Userinfo) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return conn, err
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if credentials != nil {
		password, _ := credentials.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials.Username()+":"+password)))
	}
	if err := request.Write(conn); err != nil {
		return conn, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return conn, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return conn, fmt.Errorf("proxy returned %s", response.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return conn, err
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedConn) Read(bytes []byte) (int, error) {
	return conn.reader.Read(bytes)
}

func (conn *bufferedConn) CloseWrite() error {
	if halfCloser, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return conn.Conn.Close()
}

func secureEqual(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
