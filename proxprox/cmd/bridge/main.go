package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listenAddress := flag.String("listen", "127.0.0.1:18081", "local HTTP proxy address")
	upstreamAddress := flag.String("upstream", "proxy.proxprox.spiizn.xyz:18443", "remote HTTPS proxy address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *listenAddress, *upstreamAddress); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, listenAddress, upstreamAddress string) error {
	listenHost, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return fmt.Errorf("parse local listen address %q: %w", listenAddress, err)
	}
	listenIP := net.ParseIP(listenHost)
	if listenIP == nil || !listenIP.IsLoopback() {
		return fmt.Errorf("local listen address %q must use a loopback IP", listenAddress)
	}
	upstreamHost, _, err := net.SplitHostPort(upstreamAddress)
	if err != nil {
		return fmt.Errorf("parse HTTPS proxy address %q: %w", upstreamAddress, err)
	}
	if upstreamHost == "" {
		return fmt.Errorf("HTTPS proxy address %q has an empty host", upstreamAddress)
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for Burp on %s: %w", listenAddress, err)
	}
	defer listener.Close()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-stopped:
		}
	}()
	log.Printf("Burp bridge listening on %s, forwarding to TLS proxy %s", listenAddress, upstreamAddress)
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept Burp connection on %s: %w", listenAddress, err)
		}
		go relay(client, upstreamAddress, upstreamHost)
	}
}

func relay(client net.Conn, upstreamAddress, upstreamHost string) {
	defer client.Close()
	server, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		upstreamAddress,
		&tls.Config{ServerName: upstreamHost, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
	)
	if err != nil {
		log.Printf("connect to HTTPS proxy %s: %v", upstreamAddress, err)
		return
	}
	defer server.Close()

	done := make(chan struct{})
	go func() {
		copyConnection(server, client, "Burp to proxy")
		close(done)
	}()
	copyConnection(client, server, "proxy to Burp")
	client.Close()
	<-done
}

func copyConnection(destination, source net.Conn, direction string) {
	if _, err := io.Copy(destination, source); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("copy %s: %v", direction, err)
	}
	if halfCloser, ok := destination.(interface{ CloseWrite() error }); ok {
		if err := halfCloser.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close %s write side: %v", direction, err)
		}
	}
}
