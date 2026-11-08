// Package gateway manages one gvproxy process per sandbox.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rheic/sandboxes-gateway/policy"
)

const (
	protocolTCP = "tcp"
	protocolUDP = "udp"
	guestIP     = "192.168.127.3"
	deviceIP    = "192.168.127.2"
	gatewayIP   = "192.168.127.1"
)

// ErrWindowsTransportUnavailable reports that the Windows guest-to-host
// network transport has not passed its runtime security and parity gates.
var ErrWindowsTransportUnavailable = errors.New("windows gateway transport is unavailable; QEMU network attachment has no access-controlled host endpoint")

// errEndpointExists marks an endpoint path that is already present, allowing
// the manager to attempt ownership-verified stale recovery before failing.
var errEndpointExists = errors.New("gateway endpoint path already exists")

// Config controls the gateway process manager.
type Config struct {
	GVProxy     string
	Supervisor  string
	RunDir      string
	DNSUpstream string
	// IPv6Enabled enables the experimental guest IPv6 datapath. It remains off
	// unless the daemon was explicitly started with its IPv6 acceptance flag.
	IPv6Enabled bool
	// QUICEnabled accepts UDP domain rules backed by the verified QUIC Initial
	// parser. It remains off unless the daemon was explicitly started with its
	// QUIC acceptance flag.
	QUICEnabled bool
	// OnExit is called with the sandbox name when a running gateway exits
	// unexpectedly. It runs without the manager lock held.
	OnExit func(name string)
}

// Network describes the host-side network attachment.
type Network struct {
	SocketPath   string
	QEMUEndpoint string
	MAC          string
	DeviceIP     string
	GatewayIP    string
	AuditPath    string
	Annotations  []string
}

type process struct {
	cmd       *exec.Cmd
	done      chan struct{}
	socket    string
	cfgPath   string
	logPath   string
	apiSocket string
	apiToken  string
	tokenPath string
	revision  int
	lease     io.Closer
	// stopping marks an orderly stop so the exit watcher does not report a
	// host-initiated shutdown as an unexpected gateway loss.
	stopping bool
}

// Manager owns gateway processes by sandbox name.
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	procs    map[string]process
	starting map[string]chan struct{}
	closed   bool
}

// New creates a gateway manager.
func New(cfg Config) (*Manager, error) {
	if cfg.GVProxy == "" {
		return nil, fmt.Errorf("gvproxy path is required")
	}
	if cfg.RunDir == "" {
		return nil, fmt.Errorf("run dir is required")
	}
	return &Manager{cfg: cfg, procs: make(map[string]process), starting: make(map[string]chan struct{})}, nil
}

// IPv6Enabled reports whether this manager starts gvproxy with the IPv6 datapath.
func (m *Manager) IPv6Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.IPv6Enabled
}

// SetIPv6Enabled configures the experimental datapath before any sandbox starts.
func (m *Manager) SetIPv6Enabled(enabled bool) error {
	if m == nil {
		return errors.New("gateway manager is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(m.procs) != 0 || len(m.starting) != 0 {
		return errors.New("IPv6 setting is immutable after gateway startup")
	}
	m.cfg.IPv6Enabled = enabled
	return nil
}

// QUICEnabled reports whether this manager accepts UDP domain policy.
func (m *Manager) QUICEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.QUICEnabled
}

// SetQUICEnabled configures the experimental QUIC policy before any sandbox starts.
func (m *Manager) SetQUICEnabled(enabled bool) error {
	if m == nil {
		return errors.New("gateway manager is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(m.procs) != 0 || len(m.starting) != 0 {
		return errors.New("QUIC setting is immutable after gateway startup")
	}
	m.cfg.QUICEnabled = enabled
	return nil
}

// Start launches a default-deny gateway for one sandbox.
func (m *Manager) Start(ctx context.Context, p policy.Policy) (Network, error) {
	if err := checkGatewayPlatform(); err != nil {
		return Network{}, err
	}
	if !validSandboxID(p.SandboxID) {
		return Network{}, fmt.Errorf("invalid sandbox id")
	}
	if p.Revision <= 0 {
		p.Revision = 1
	}
	name := p.SandboxID
	if err := m.reserveStart(name); err != nil {
		return Network{}, err
	}
	defer func() {
		m.mu.Lock()
		finished := m.starting[name]
		delete(m.starting, name)
		close(finished)
		m.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return Network{}, err
	}
	if err := os.MkdirAll(m.cfg.RunDir, 0o700); err != nil {
		return Network{}, err
	}
	socket, apiSocket, tokenPath, err := gatewayEndpoints(m.cfg.RunDir, name)
	if err != nil {
		return Network{}, err
	}
	if err := m.ensureEndpointAvailable(socket); err != nil {
		return Network{}, err
	}
	cfgPath := filepath.Join(m.cfg.RunDir, name+".yaml")
	logPath := filepath.Join(m.cfg.RunDir, name+".gateway.log")
	if err := m.ensureEndpointAvailable(apiSocket); err != nil {
		return Network{}, err
	}
	return m.launch(ctx, p, socket, cfgPath, logPath, apiSocket, tokenPath)
}

// ensureEndpointAvailable rejects endpoints that are live or unowned. A stale
// socket left by a crashed gateway is removed only after verifying that it is
// a socket directly inside the run directory and that nothing is listening on
// it; anything else fails closed and is left untouched.
func (m *Manager) ensureEndpointAvailable(endpoint string) error {
	err := ensureGatewayEndpointAvailable(endpoint)
	if err == nil || !errors.Is(err, errEndpointExists) {
		return err
	}
	if recoverErr := m.recoverStaleEndpoint(endpoint); recoverErr != nil {
		return err
	}
	return ensureGatewayEndpointAvailable(endpoint)
}

// recoverStaleEndpoint removes an existing endpoint path only when it is a
// stale socket owned by the run directory: no listener answers a bounded
// dial. A live listener or a non-socket path is left untouched and reported.
func (m *Manager) recoverStaleEndpoint(endpoint string) error {
	if strings.HasPrefix(endpoint, "tcp://") {
		return errors.New("tcp endpoint recovery is not supported")
	}
	if err := m.requireOwnedSocketPath(endpoint); err != nil {
		return err
	}
	conn, dialErr := net.DialTimeout("unix", endpoint, 300*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("gateway endpoint is live")
	}
	return m.removeOwnedSocket(endpoint)
}

// requireOwnedSocketPath verifies through Lstat that the path is a socket
// directly inside the configured run directory, without following symlinks.
func (m *Manager) requireOwnedSocketPath(path string) error {
	runDir, err := filepath.Abs(m.cfg.RunDir)
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	if dir != runDir {
		return errors.New("endpoint is outside the gateway run directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("endpoint is not an owned socket")
	}
	return nil
}

func (m *Manager) reserveStart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, active := m.procs[name]
	_, starting := m.starting[name]
	if m.closed {
		return errors.New("gateway manager is closed")
	}
	if active || starting {
		return errors.New("gateway is already running or starting")
	}
	m.starting[name] = make(chan struct{})
	return nil
}

func ensureSocketPathAvailable(socket string) error {
	if _, err := os.Lstat(socket); err == nil {
		return errEndpointExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect gateway socket: %w", err)
	}
	return nil
}

func (m *Manager) launch(ctx context.Context, p policy.Policy, socket, cfgPath, logPath, apiSocket, tokenPath string) (Network, error) {
	name := p.SandboxID
	if err := writeConfig(cfgPath, p, m.cfg.DNSUpstream, m.cfg.IPv6Enabled, m.cfg.QUICEnabled); err != nil {
		return Network{}, err
	}
	apiToken, err := createGatewayAPIToken(tokenPath)
	if err != nil {
		return Network{}, err
	}
	logFile, err := openManagedFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return Network{}, errors.Join(err, removeManagedGatewaySecret(tokenPath))
	}
	cmd, lease, err := startManagedGateway(m.cfg.Supervisor, m.cfg.GVProxy, cfgPath, socket, apiSocket, tokenPath, logFile)
	if err != nil {
		_ = logFile.Close()
		return Network{}, errors.Join(err, removeManagedGatewaySecret(tokenPath))
	}
	_ = logFile.Close()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = lease.Close()
		close(done)
	}()
	proc := process{cmd: cmd, done: done, socket: socket, cfgPath: cfgPath, logPath: logPath, apiSocket: apiSocket, apiToken: apiToken, tokenPath: tokenPath, revision: p.Revision, lease: lease}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return Network{}, m.abortStart(name, proc, errors.New("gateway exited before becoming ready"))
		default:
		}
		if gatewayEndpointReady(ctx, socket, apiSocket, apiToken, done) {
			m.mu.Lock()
			if m.closed {
				m.mu.Unlock()
				return Network{}, m.abortStart(name, proc, errors.New("gateway manager closed during startup"))
			}
			m.procs[name] = proc
			m.mu.Unlock()
			go m.watch(name, proc, done)
			mac := MAC(name)
			return Network{
				SocketPath:   socket,
				QEMUEndpoint: qemuNetworkEndpoint(socket),
				MAC:          mac,
				DeviceIP:     deviceIP,
				GatewayIP:    gatewayIP,
				AuditPath:    p.AuditPath,
				Annotations:  gatewayNetworkAnnotations(socket, mac),
			}, nil
		}
		select {
		case <-ctx.Done():
			return Network{}, m.abortStart(name, proc, ctx.Err())
		case <-done:
			return Network{}, m.abortStart(name, proc, errors.New("gateway exited before becoming ready"))
		case <-time.After(100 * time.Millisecond):
		}
	}
	return Network{}, m.abortStart(name, proc, errors.New("gateway did not become ready"))
}

func (m *Manager) abortStart(name string, proc process, cause error) error {
	_ = proc.lease.Close()
	var cleanupErr error
	select {
	case <-proc.done:
	case <-time.After(2 * time.Second):
		cleanupErr = errors.New("gateway supervisor did not stop after lease closed")
	}
	if cleanupErr != nil {
		m.mu.Lock()
		m.procs[name] = proc
		m.mu.Unlock()
		go m.watch(name, proc, proc.done)
	} else {
		cleanupErr = errors.Join(cleanupErr, m.removeOwnedSocket(proc.socket), m.removeOwnedSocket(proc.apiSocket), removeManagedGatewaySecret(proc.tokenPath))
	}
	return errors.Join(cause, cleanupErr)
}

// validSandboxID confines generated file names to the configured run directory.
func validSandboxID(id string) bool {
	if id == "" || len(id) > 63 || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func (m *Manager) markStopping(name string, p process) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.procs[name]; ok && current.cmd == p.cmd {
		current.stopping = true
		m.procs[name] = current
	}
}

// watch forgets a gateway that exited after startup and reports the loss. A
// gateway restart cannot reuse the guest's unixgram peer, so the sandbox must
// be recreated instead of silently keeping a running VM without network.
func (m *Manager) watch(name string, proc process, done <-chan struct{}) {
	<-done
	m.mu.Lock()
	current, ok := m.procs[name]
	unexpected := ok && current.cmd == proc.cmd && !current.stopping
	if ok && current.cmd == proc.cmd {
		delete(m.procs, name)
	}
	onExit := m.cfg.OnExit
	m.mu.Unlock()
	_ = m.removeOwnedSocket(proc.socket)
	_ = m.removeOwnedSocket(proc.apiSocket)
	_ = removeManagedGatewaySecret(proc.tokenPath)
	if unexpected && onExit != nil {
		onExit(name)
	}
}

// removeOwnedSocket removes a leftover socket path only when it is a socket
// directly inside the configured run directory. Anything else is left alone.
func (m *Manager) removeOwnedSocket(path string) error {
	if path == "" {
		return nil
	}
	if strings.HasPrefix(path, "tcp://") {
		return nil
	}
	runDir, err := filepath.Abs(m.cfg.RunDir)
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	if dir != runDir {
		return nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	return os.Remove(path)
}

// Stop terminates the sandbox gateway.
func (m *Manager) Stop(ctx context.Context, name string) error {
	m.mu.Lock()
	p, ok := m.procs[name]
	_, starting := m.starting[name]
	m.mu.Unlock()
	switch {
	case starting:
		return errors.New("gateway is starting")
	case !ok:
		return m.clearStaleSockets(name)
	}
	if err := m.stopProcess(ctx, name, p); err != nil {
		return err
	}
	if err := m.removeOwnedSocket(p.socket); err != nil {
		return fmt.Errorf("remove gateway socket: %w", err)
	}
	if err := m.removeOwnedSocket(p.apiSocket); err != nil {
		return fmt.Errorf("remove gateway services socket: %w", err)
	}
	if err := removeManagedGatewaySecret(p.tokenPath); err != nil {
		return fmt.Errorf("remove gateway API token: %w", err)
	}
	return verifyGatewayEndpointStopped(p.socket)
}

// clearStaleSockets removes paths left by a gateway that died, or by a
// previous daemon run. Without this they would block every later start.
func (m *Manager) clearStaleSockets(name string) error {
	for _, path := range staleGatewayEndpoints(m.cfg.RunDir, name) {
		if err := m.removeOwnedSocket(path); err != nil {
			return fmt.Errorf("remove stale gateway socket: %w", err)
		}
	}
	if err := removeManagedGatewaySecret(filepath.Join(m.cfg.RunDir, name+".api-token")); err != nil {
		return fmt.Errorf("remove stale gateway API token: %w", err)
	}
	return nil
}

func (m *Manager) stopProcess(ctx context.Context, name string, p process) error {
	m.markStopping(name, p)
	_ = p.lease.Close()
	select {
	case <-p.done:
	default:
		select {
		case <-p.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return errors.New("gateway supervisor did not stop after lease closed")
		}
	}
	m.mu.Lock()
	if current, ok := m.procs[name]; ok && current.cmd == p.cmd {
		delete(m.procs, name)
	}
	m.mu.Unlock()
	return nil
}

// ErrReloadUnverified reports that the current gvproxy has no revision ACK.
var ErrReloadUnverified = errors.New("gateway policy reload has no verified acknowledgement")

// Reload rewrites the gateway config, asks the platform control channel to
// apply the policy, and verifies its revision acknowledgement. Without an
// acknowledgement the gateway is stopped and the error fails closed.
func (m *Manager) Reload(ctx context.Context, p policy.Policy) error {
	if !validSandboxID(p.SandboxID) {
		return fmt.Errorf("invalid sandbox id")
	}
	m.mu.Lock()
	proc, ok := m.procs[p.SandboxID]
	starting := m.starting[p.SandboxID]
	m.mu.Unlock()
	if starting != nil {
		select {
		case <-starting:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
		proc, ok = m.procs[p.SandboxID]
		m.mu.Unlock()
	}
	if !ok {
		return fmt.Errorf("gateway for %s is not running", p.SandboxID)
	}
	if p.Revision <= 0 {
		return fmt.Errorf("policy revision must be positive")
	}
	if err := validatePolicy(p, m.cfg.QUICEnabled); err != nil {
		return err
	}
	if p.Revision <= proc.revision {
		return fmt.Errorf("policy revision %d must advance past %d", p.Revision, proc.revision)
	}
	if err := writeConfig(proc.cfgPath, p, m.cfg.DNSUpstream, m.cfg.IPv6Enabled, m.cfg.QUICEnabled); err != nil {
		return err
	}
	offset, err := fileSize(proc.logPath)
	if err != nil {
		return err
	}
	ackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := reloadGateway(ackCtx, proc, p, offset); err != nil {
		stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		stopErr := m.Stop(stopCtx, p.SandboxID)
		stopCancel()
		return errors.Join(ErrReloadUnverified, err, stopErr)
	}
	m.mu.Lock()
	if current, ok := m.procs[p.SandboxID]; ok && current.cmd == proc.cmd {
		current.revision = p.Revision
		m.procs[p.SandboxID] = current
	}
	m.mu.Unlock()
	return nil
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("inspect gateway log: %w", err)
	}
	return info.Size(), nil
}

func waitForReloadAck(ctx context.Context, proc process, offset int64, revision int) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	want := fmt.Sprintf("egress policy reloaded revision=%d", revision)
	for {
		if data, err := readFrom(proc.logPath, offset); err == nil && strings.Contains(string(data), want) {
			return nil
		}
		select {
		case <-proc.done:
			return errors.New("gateway exited before acknowledging policy reload")
		case <-ctx.Done():
			return errors.New("gateway did not acknowledge policy reload")
		case <-ticker.C:
		}
	}
}

func readFrom(path string, offset int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- managed gateway log in the configured run directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, 64*1024))
}

// Close stops all managed gateways.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	names := make([]string, 0, len(m.procs))
	for name := range m.procs {
		names = append(names, name)
	}
	starting := len(m.starting) != 0
	m.mu.Unlock()
	for _, name := range names {
		if err := m.Stop(ctx, name); err != nil {
			return err
		}
	}
	if starting {
		return errors.New("gateway startup still in progress")
	}
	return nil
}

// MAC returns a deterministic local MAC for a sandbox.
func MAC(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("fa:43:25:%02x:%02x:%02x", sum[0], sum[1], sum[2])
}

func writeConfig(path string, p policy.Policy, dnsUpstream string, ipv6Enabled, quicEnabled bool) error {
	if err := validatePolicy(p, quicEnabled); err != nil {
		return err
	}
	if err := validateIPv6RuleCapability(p.Allow, p.Deny, ipv6Enabled); err != nil {
		return err
	}
	if err := validateIPv6PortCapability(p.Ports, ipv6Enabled); err != nil {
		return err
	}
	if err := validateDomainUpstream(p, dnsUpstream); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if p.AuditPath != "" {
		if err := os.MkdirAll(filepath.Dir(p.AuditPath), 0o700); err != nil {
			return err
		}
	}
	file, err := openManagedFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate gateway config: %w", err)
	}
	if _, err := file.WriteString(renderConfig(p, dnsUpstream, ipv6Enabled)); err != nil {
		return fmt.Errorf("write gateway config: %w", err)
	}
	return nil
}

// validatePolicy rejects rule forms the configured gvproxy policy engine
// cannot enforce.
func validatePolicy(p policy.Policy, quicEnabled bool) error {
	if err := validatePolicyRules(p.Allow, "allow"); err != nil {
		return err
	}
	if err := validatePolicyRules(p.Deny, "deny"); err != nil {
		return err
	}
	if err := policy.ValidateEnforcementWith(p.Allow, p.Deny, policy.Capabilities{QUIC: quicEnabled}); err != nil {
		return err
	}
	return validatePolicyPorts(p.Ports)
}

func validatePolicyRules(rules []policy.Rule, name string) error {
	for i, rule := range rules {
		protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
		if protocol != protocolTCP && protocol != protocolUDP {
			return fmt.Errorf("%s rule %d: protocol must be tcp or udp", name, i)
		}
		switch {
		case rule.Domain != "" && rule.CIDR != "":
			return fmt.Errorf("%s rule %d: domain and cidr are mutually exclusive", name, i)
		case rule.Domain != "":
			if !validDomainRule(rule.Domain) {
				return fmt.Errorf("%s rule %d: invalid domain %q", name, i, rule.Domain)
			}
		case rule.CIDR == "":
			return fmt.Errorf("%s rule %d: cidr or domain is required", name, i)
		default:
			if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
				return fmt.Errorf("%s rule %d: invalid cidr %q: %w", name, i, rule.CIDR, err)
			}
		}
	}
	return nil
}

func validateDomainUpstream(p policy.Policy, dnsUpstream string) error {
	if dnsUpstream != "" {
		return nil
	}
	for _, rules := range [][]policy.Rule{p.Allow, p.Deny} {
		for _, rule := range rules {
			if rule.Domain != "" {
				return errors.New("domain policy requires a DNS upstream (--dns-upstream or settings dns.upstream)")
			}
		}
	}
	return nil
}

func validDomainRule(pattern string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	if !validDomainHead(pattern) {
		return false
	}
	base := strings.TrimPrefix(strings.TrimPrefix(pattern, "**."), "*.")
	if base == "" || strings.Contains(base, "*") {
		return false
	}
	for _, label := range strings.Split(base, ".") {
		if !validDomainLabel(label) {
			return false
		}
	}
	return true
}

// validDomainHead rejects empty, oversized, whitespace, glob-star and IP
// literal patterns. A domain rule matches TLS hostnames; an IP literal never
// can, so accepting one would create a rule that silently matches nothing.
func validDomainHead(pattern string) bool {
	if pattern == "" || len(pattern) > 253 || strings.ContainsAny(pattern, "\\ ") {
		return false
	}
	return net.ParseIP(pattern) == nil
}

func validDomainLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if _, err := pathpkg.Match(strings.ReplaceAll(label, "[!", "[^"), "example"); err != nil {
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '?' || r == '[' || r == ']' || r == '!' {
			continue
		}
		return false
	}
	return true
}

func validatePolicyPorts(ports []policy.Port) error {
	for i, port := range ports {
		if port.Host == 0 || port.Guest == 0 {
			return fmt.Errorf("port %d: host and guest ports must be non-zero", i)
		}
		if portProto(port) != protocolTCP && portProto(port) != protocolUDP {
			return fmt.Errorf("port %d: protocol must be tcp or udp", i)
		}
		if port.HostIP == "" {
			continue
		}
		ip := net.ParseIP(port.HostIP)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("port %d: host IP must be loopback", i)
		}
	}
	return nil
}

func validateIPv6RuleCapability(allow, deny []policy.Rule, ipv6Enabled bool) error {
	if ipv6Enabled {
		return nil
	}
	for _, scope := range []struct {
		name  string
		rules []policy.Rule
	}{{"allow", allow}, {"deny", deny}} {
		for index, rule := range scope.rules {
			if rule.CIDR == "" {
				continue
			}
			ip, _, err := net.ParseCIDR(rule.CIDR)
			if err == nil && ip.To4() == nil {
				return fmt.Errorf("%s rule %d: IPv6 CIDR requires the experimental IPv6 capability", scope.name, index)
			}
		}
	}
	return nil
}

func validateIPv6PortCapability(ports []policy.Port, ipv6Enabled bool) error {
	if ipv6Enabled {
		return nil
	}
	for index, port := range ports {
		ip := net.ParseIP(port.HostIP)
		if ip != nil && ip.Equal(net.IPv6loopback) {
			return fmt.Errorf("port %d: IPv6 host forwarding requires the experimental IPv6 capability", index)
		}
	}
	return nil
}

func portProto(port policy.Port) string {
	protocol := strings.ToLower(strings.TrimSpace(port.Proto))
	if protocol == "" {
		return protocolTCP
	}
	return protocol
}

func renderConfig(p policy.Policy, dnsUpstream string, ipv6Enabled bool) string {
	var b strings.Builder
	b.WriteString("stack:\n")
	b.WriteString("  subnet: 192.168.127.0/24\n")
	b.WriteString("  gatewayIP: 192.168.127.1\n")
	if ipv6Enabled {
		b.WriteString("  ipv6Enabled: true\n")
	}
	b.WriteString("  deviceIP: 192.168.127.2\n")
	b.WriteString("  hostIP: 192.168.127.254\n")
	b.WriteString("  mtu: 1500\n")
	if dnsUpstream != "" {
		fmt.Fprintf(&b, "  dnsUpstream: %s\n", strconv.Quote(dnsUpstream))
	}
	b.WriteString("  nat:\n    192.168.127.254: 127.0.0.1\n")
	b.WriteString("  gatewayVirtualIPs:\n    - 192.168.127.254\n")
	if len(p.Ports) > 0 {
		b.WriteString("  forwards:\n")
		for _, port := range p.Ports {
			local := portLocal(port)
			if portProto(port) == protocolUDP {
				local = "udp:" + local
			}
			fmt.Fprintf(&b, "    %s: %s\n",
				strconv.Quote(local),
				strconv.Quote(guestForwardRemote(port)))
		}
	}
	b.WriteString("  egressPolicy:\n")
	fmt.Fprintf(&b, "    revision: %s\n", strconv.Quote(strconv.Itoa(p.Revision)))
	fmt.Fprintf(&b, "    sandboxID: %s\n", strconv.Quote(p.SandboxID))
	fmt.Fprintf(&b, "    auditLog: %s\n", strconv.Quote(p.AuditPath))
	writeRules(&b, "allow", p.Allow)
	writeRules(&b, "deny", p.Deny)
	return b.String()
}

func writeRules(b *strings.Builder, name string, rules []policy.Rule) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(b, "    %s:\n", name)
	for _, r := range rules {
		proto := r.Protocol
		if proto == "" {
			proto = protocolTCP
		}
		fmt.Fprintf(b, "      - protocol: %s\n", strconv.Quote(proto))
		if r.ID != "" {
			fmt.Fprintf(b, "        id: %s\n", strconv.Quote(r.ID))
		}
		if r.CIDR != "" {
			fmt.Fprintf(b, "        cidr: %s\n", strconv.Quote(r.CIDR))
		}
		if r.Domain != "" {
			fmt.Fprintf(b, "        domain: %s\n", strconv.Quote(r.Domain))
		}
		if r.Port != 0 {
			fmt.Fprintf(b, "        port: %d\n", r.Port)
		}
	}
}

func shortSocket(path string) error {
	if len(path) > 100 {
		return fmt.Errorf("unix socket path is too long (%d bytes): %s", len(path), path)
	}
	return nil
}

type forwardAPI struct {
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	Protocol string `json:"protocol"`
}

// SetPorts reconciles gvproxy's TCP forwarders with the requested host->guest
// mappings through its private services API.
func (m *Manager) SetPorts(ctx context.Context, name string, ports []policy.Port) error {
	m.mu.Lock()
	proc, ok := m.procs[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("gateway for %s is not running", name)
	}
	if err := validatePolicyPorts(ports); err != nil {
		return err
	}
	if err := validateIPv6PortCapability(ports, m.cfg.IPv6Enabled); err != nil {
		return err
	}
	if err := waitServicesAPI(ctx, proc); err != nil {
		return err
	}
	current, err := listForwardsAuth(ctx, proc.apiSocket, proc.apiToken)
	if err != nil {
		return err
	}
	return applyForwardDiffAuth(ctx, proc.apiSocket, proc.apiToken, current, desiredForwards(ports))
}

func waitServicesAPI(ctx context.Context, proc process) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := listForwardsAuth(ctx, proc.apiSocket, proc.apiToken); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("gateway services API did not become ready")
		}
		select {
		case <-proc.done:
			return errors.New("gateway exited before its services API became ready")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func desiredForwards(ports []policy.Port) map[string]forwardAPI {
	desired := make(map[string]forwardAPI, len(ports))
	for _, port := range ports {
		protocol := portProto(port)
		if protocol != protocolTCP && protocol != protocolUDP {
			continue
		}
		local := portLocal(port)
		key := protocol + "|" + local
		desired[key] = forwardAPI{Local: local, Remote: guestForwardRemote(port), Protocol: protocol}
	}
	return desired
}

func guestForwardRemote(port policy.Port) string {
	if ip := net.ParseIP(port.HostIP); ip != nil && ip.Equal(net.IPv6loopback) {
		return fmt.Sprintf("guest-ipv6:%d", port.Guest)
	}
	return fmt.Sprintf("%s:%d", guestIP, port.Guest)
}

func portLocal(port policy.Port) string {
	hostIP := port.HostIP
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	return net.JoinHostPort(hostIP, strconv.Itoa(int(port.Host)))
}

func applyForwardDiffAuth(ctx context.Context, socket, token string, current []forwardAPI, desired map[string]forwardAPI) error {
	currentSet := make(map[string]struct{}, len(current))
	for _, forward := range current {
		protocol := forward.Protocol
		if protocol == "" {
			protocol = protocolTCP
		}
		if protocol != protocolTCP && protocol != protocolUDP {
			continue
		}
		key := protocol + "|" + forward.Local
		currentSet[key] = struct{}{}
		if _, keep := desired[key]; keep {
			continue
		}
		if err := postForwardAuth(ctx, socket, token, "/services/forwarder/unexpose", forwardAPI{Local: forward.Local, Protocol: protocol}); err != nil {
			return err
		}
	}
	for key, forward := range desired {
		if _, exists := currentSet[key]; exists {
			continue
		}
		if err := postForwardAuth(ctx, socket, token, "/services/forwarder/expose", forward); err != nil {
			return err
		}
	}
	return nil
}

func listForwards(ctx context.Context, socket string) ([]forwardAPI, error) {
	return listForwardsAuth(ctx, socket, "")
}

func listForwardsAuth(ctx context.Context, endpoint, token string) ([]forwardAPI, error) {
	if err := validateGatewayAPIAuth(endpoint, token); err != nil {
		return nil, err
	}
	client, err := gatewayHTTPClient(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://gvproxy/services/forwarder/all", http.NoBody)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list gateway forwards: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("list gateway forwards: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var forwards []forwardAPI
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&forwards); err != nil {
		return nil, fmt.Errorf("decode gateway forwards: %w", err)
	}
	return forwards, nil
}

func postForwardAuth(ctx context.Context, gatewayEndpoint, token, endpoint string, payload forwardAPI) error {
	if err := validateGatewayAPIAuth(gatewayEndpoint, token); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://gvproxy"+endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client, err := gatewayHTTPClient(gatewayEndpoint)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway forward API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gateway forward API: status %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func gatewayHTTPClient(endpoint string) (*http.Client, error) {
	var dialNetwork, dialAddress string
	switch {
	case strings.HasPrefix(endpoint, "tcp://"):
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "tcp" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Opaque != "" {
			return nil, errors.New("gateway TCP API must use IPv4 loopback")
		}
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("gateway TCP API endpoint is invalid")
		}
		dialNetwork, dialAddress = "tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))
	default:
		if endpoint == "" {
			return nil, errors.New("gateway API endpoint is required")
		}
		dialNetwork, dialAddress = "unix", endpoint
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, dialNetwork, dialAddress)
			},
		},
		Timeout: 5 * time.Second,
	}, nil
}
