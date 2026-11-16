package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type Rule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	ProgramSlug string `json:"program_slug"`
	Upstream    string `json:"upstream,omitempty"`
	VPN         string `json:"vpn,omitempty"`
}

type Upstream struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type VPN struct {
	Name    string `json:"name"`
	Gateway string `json:"gateway"`
}

type State struct {
	Version   int        `json:"version"`
	Rules     []Rule     `json:"rules"`
	Upstreams []Upstream `json:"upstreams"`
	VPNs      []VPN      `json:"vpns"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

type Decision struct {
	Host        string `json:"host"`
	Pattern     string `json:"pattern,omitempty"`
	ProgramSlug string `json:"program_slug,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
	VPN         string `json:"vpn,omitempty"`
	Route       string `json:"route"`
}

var identifierRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var domainLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func newStore(path string) (*Store, error) {
	s := &Store{path: path}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		s.state = State{Version: 1, Rules: []Rule{}, Upstreams: []Upstream{}, VPNs: []VPN{}}
		if err := s.save(s.state); err != nil {
			return nil, fmt.Errorf("initialize configuration %q: %w", path, err)
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s.state); err != nil {
		return nil, fmt.Errorf("decode configuration %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("configuration %q contains trailing data: %v", path, err)
	}
	if err := validateState(s.state); err != nil {
		return nil, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	return s, nil
}

func (s *Store) snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func cloneState(state State) State {
	state.Rules = append([]Rule{}, state.Rules...)
	state.Upstreams = append([]Upstream{}, state.Upstreams...)
	state.VPNs = append([]VPN{}, state.VPNs...)
	return state
}

func (s *Store) update(change func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := change(&next); err != nil {
		return err
	}
	if err := validateState(next); err != nil {
		return err
	}
	if err := s.save(next); err != nil {
		return fmt.Errorf("persist configuration %q: %w", s.path, err)
	}
	s.state = next
	return nil
}

func (s *Store) save(state State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".proxprox-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	return nil
}

func newID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func validateState(state State) error {
	if state.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d; expected 1", state.Version)
	}
	upstreams := make(map[string]bool)
	for _, upstream := range state.Upstreams {
		if err := validateIdentifier(upstream.Name); err != nil {
			return fmt.Errorf("upstream name: %w", err)
		}
		if upstreams[upstream.Name] {
			return fmt.Errorf("duplicate upstream %q", upstream.Name)
		}
		upstreams[upstream.Name] = true
		if _, err := parseUpstreamURL(upstream.URL); err != nil {
			return fmt.Errorf("upstream %q: %w", upstream.Name, err)
		}
	}
	vpns := make(map[string]bool)
	for _, vpn := range state.VPNs {
		if err := validateIdentifier(vpn.Name); err != nil {
			return fmt.Errorf("VPN name: %w", err)
		}
		if vpns[vpn.Name] {
			return fmt.Errorf("duplicate VPN %q", vpn.Name)
		}
		vpns[vpn.Name] = true
		if err := validateAddress(vpn.Gateway); err != nil {
			return fmt.Errorf("VPN %q gateway: %w", vpn.Name, err)
		}
	}
	patterns := make(map[string]bool)
	ids := make(map[string]bool)
	for _, rule := range state.Rules {
		if rule.ID == "" || ids[rule.ID] {
			return fmt.Errorf("missing or duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = true
		if err := validatePattern(rule.Pattern); err != nil {
			return fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if patterns[rule.Pattern] {
			return fmt.Errorf("duplicate pattern %q", rule.Pattern)
		}
		patterns[rule.Pattern] = true
		if err := validateIdentifier(rule.ProgramSlug); err != nil {
			return fmt.Errorf("rule %q program slug: %w", rule.ID, err)
		}
		if rule.Upstream != "" && !upstreams[rule.Upstream] {
			return fmt.Errorf("rule %q references unknown upstream %q", rule.ID, rule.Upstream)
		}
		if rule.VPN != "" && !vpns[rule.VPN] {
			return fmt.Errorf("rule %q references unknown VPN %q", rule.ID, rule.VPN)
		}
	}
	return nil
}

func validateIdentifier(value string) error {
	if !identifierRE.MatchString(value) {
		return fmt.Errorf("%q must contain 1-64 lowercase letters, digits, underscores or hyphens and start with a letter or digit", value)
	}
	return nil
}

func validatePattern(pattern string) error {
	if strings.HasPrefix(pattern, "*.") {
		return validateHost(pattern[2:])
	}
	return validateHost(pattern)
}

func validateHost(host string) error {
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return fmt.Errorf("invalid host %q: use lowercase without a trailing dot", host)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("host %q is too long", host)
	}
	for _, label := range strings.Split(host, ".") {
		if !domainLabelRE.MatchString(label) {
			return fmt.Errorf("invalid host label %q in %q", label, host)
		}
	}
	return nil
}

func validateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%q must be host:port: %w", address, err)
	}
	if err := validateHost(strings.ToLower(host)); err != nil {
		return err
	}
	if port == "" {
		return fmt.Errorf("missing port in %q", address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid numeric port in %q", address)
	}
	return nil
}

func parseUpstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		var parseError *url.Error
		if errors.As(err, &parseError) {
			return nil, fmt.Errorf("invalid upstream URL syntax: %w", parseError.Err)
		}
		return nil, fmt.Errorf("invalid upstream URL syntax: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("upstream URL must use http or https")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream URL must not contain a path, query or fragment")
	}
	if err := validateAddress(u.Host); err != nil {
		return nil, fmt.Errorf("upstream address: %w", err)
	}
	return u, nil
}

func (state State) decide(host string) Decision {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	decision := Decision{Host: host, Route: "direct"}
	bestScore := -1
	for _, rule := range state.Rules {
		score := -1
		if rule.Pattern == host {
			score = 1000 + len(rule.Pattern)
		} else if strings.HasPrefix(rule.Pattern, "*.") {
			suffix := rule.Pattern[1:]
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				score = len(suffix)
			}
		}
		if score > bestScore {
			bestScore = score
			decision.Pattern = rule.Pattern
			decision.ProgramSlug = rule.ProgramSlug
			decision.RuleID = rule.ID
			decision.Upstream = rule.Upstream
			decision.VPN = rule.VPN
		}
	}
	if decision.VPN != "" {
		decision.Route = "vpn"
	}
	if decision.Upstream != "" {
		if decision.VPN != "" {
			decision.Route = "vpn_upstream"
		} else {
			decision.Route = "upstream"
		}
	}
	return decision
}

func (state State) getUpstream(name string) (Upstream, bool) {
	for _, item := range state.Upstreams {
		if item.Name == name {
			return item, true
		}
	}
	return Upstream{}, false
}

func (state State) getVPN(name string) (VPN, bool) {
	for _, item := range state.VPNs {
		if item.Name == name {
			return item, true
		}
	}
	return VPN{}, false
}
