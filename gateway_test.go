package gateway

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-gateway/policy"
)

func TestRenderConfig(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision:  2,
		SandboxID: "dev",
		AuditPath: "/tmp/dev.audit.jsonl",
		Allow: []policy.Rule{
			{ID: "rul_allow_cidr", Protocol: "tcp", Domain: "api.example.test", Port: 443},
			{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443},
		},
		Deny: []policy.Rule{
			{Protocol: "udp", CIDR: "10.1.0.0/16", Port: 53},
		},
		Ports: []policy.Port{{Host: 8080, Guest: 3000}},
	}, "1.1.1.1:53", false)
	for _, want := range []string{
		"egressPolicy:",
		`revision: "2"`,
		`sandboxID: "dev"`,
		`auditLog: "/tmp/dev.audit.jsonl"`,
		"    allow:",
		`cidr: "10.0.0.0/8"`,
		`id: "rul_allow_cidr"`,
		`domain: "api.example.test"`,
		"    deny:",
		`protocol: "udp"`,
		`"127.0.0.1:8080": "192.168.127.3:3000"`,
		`dnsUpstream: "1.1.1.1:53"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in config:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "ipv6Enabled:") {
		t.Fatal("IPv6 must remain disabled by default")
	}
	if strings.Contains(cfg, ipv6HostServicesGuest) {
		t.Fatal("IPv6 host-services NAT entry must remain disabled by default")
	}
}

func TestRenderConfigEnablesExperimentalIPv6Explicitly(t *testing.T) {
	cfg := renderConfig(policy.Policy{Revision: 1, SandboxID: "ipv6"}, "", true)
	if !strings.Contains(cfg, "  ipv6Enabled: true\n") {
		t.Fatalf("explicit IPv6 config missing:\n%s", cfg)
	}
	if !strings.Contains(cfg, "  nat:\n    192.168.127.254: 127.0.0.1\n") {
		t.Fatalf("IPv4 host-services NAT entry missing:\n%s", cfg)
	}
	wantNAT := "    \"" + ipv6HostServicesGuest + "\": \"" + ipv6HostServicesHost + "\"\n"
	if !strings.Contains(cfg, wantNAT) {
		t.Fatalf("explicit IPv6 host-services NAT entry %q missing:\n%s", wantNAT, cfg)
	}
	if got := strings.Count(cfg, ipv6HostServicesGuest); got != 1 {
		t.Fatalf("IPv6 host-services NAT entry rendered %d times, want 1:\n%s", got, cfg)
	}
	manager, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir(), IPv6Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.IPv6Enabled() {
		t.Fatal("manager failed to report explicit IPv6 capability")
	}
}

func TestIPv6HostServicesNATAddressDiscipline(t *testing.T) {
	guest := net.ParseIP(ipv6HostServicesGuest)
	if guest == nil || guest.To4() != nil {
		t.Fatalf("host-services guest address %q is not a global-shape IPv6 address", ipv6HostServicesGuest)
	}
	_, guestPrefix, err := net.ParseCIDR("fd72:6865:6963::/64")
	if err != nil {
		t.Fatal(err)
	}
	if guestPrefix.Contains(guest) {
		t.Fatalf("host-services address %s must stay outside the guest /64", ipv6HostServicesGuest)
	}
	_, ula, err := net.ParseCIDR("fc00::/7")
	if err != nil {
		t.Fatal(err)
	}
	if !ula.Contains(guest) {
		t.Fatalf("host-services address %s is not an IPv6 ULA", ipv6HostServicesGuest)
	}
	host := net.ParseIP(ipv6HostServicesHost)
	if host == nil || !host.IsLoopback() {
		t.Fatalf("host-services destination %q is not host loopback", ipv6HostServicesHost)
	}
}

func TestRenderConfigSupportsLoopbackIPv6AndUDP(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision:  3,
		SandboxID: "dev6",
		Ports: []policy.Port{
			{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "::1"},
			{Host: 8081, Guest: 3001, Proto: "udp", HostIP: "127.0.0.1"},
		},
	}, "", true)
	for _, want := range []string{`"[::1]:8080": "guest-ipv6:3000"`, `"udp:127.0.0.1:8081": "192.168.127.3:3001"`} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in config:\n%s", want, cfg)
		}
	}
}

func TestDesiredForwardsKeysIncludeHostIP(t *testing.T) {
	forwards := desiredForwards([]policy.Port{
		{Host: 8080, Guest: 3000, Proto: "tcp"},
		{Host: 8080, Guest: 3001, Proto: "tcp", HostIP: "::1"},
		{Host: 8080, Guest: 3002, Proto: "udp", HostIP: "::1"},
	})
	if len(forwards) != 3 {
		t.Fatalf("forwards=%+v", forwards)
	}
	if forwards["tcp|127.0.0.1:8080"].Remote != "192.168.127.3:3000" || forwards["tcp|[::1]:8080"].Remote != "guest-ipv6:3001" || forwards["udp|[::1]:8080"].Remote != "guest-ipv6:3002" {
		t.Fatalf("forwards=%+v", forwards)
	}
}

func TestStartDoesNotRemoveExistingSocketPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.sock")
	if err := os.WriteFile(path, []byte("owned elsewhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), policy.Policy{SandboxID: "dev"}); err == nil {
		t.Fatal("start accepted an existing socket path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "owned elsewhere" {
		t.Fatalf("existing file changed: %q, %v", data, err)
	}
}

func TestGatewayFilesRejectLinksWithoutChangingTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		link func(string, string) error
	}{
		{"symlink", os.Symlink},
		{"hardlink", os.Link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := tc.link(target, path); err != nil {
				t.Fatal(err)
			}
			if err := writeConfig(path, policy.Policy{SandboxID: "dev"}, "", false, false); err == nil {
				t.Fatal("linked config accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "unchanged" {
				t.Fatalf("target changed: %q, %v", data, err)
			}
		})
	}
	path := filepath.Join(dir, "valid.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "dev"}, "", false, false); err != nil {
		t.Fatalf("private regular config rejected: %v", err)
	}
}

func TestMACDeterministic(t *testing.T) {
	first := MAC("dev")
	second := MAC("dev")
	if first != second {
		t.Fatal("MAC must be deterministic")
	}
	if MAC("dev") == MAC("prod") {
		t.Fatal("different sandboxes need different MACs")
	}
}

func TestValidatePolicyFailsClosedForUnsupportedRules(t *testing.T) {
	tests := []struct {
		name string
		rule policy.Rule
	}{
		{name: "domain and cidr", rule: policy.Rule{Protocol: "tcp", Domain: "registry.example", CIDR: "192.0.2.0/24", Port: 443}},
		{name: "invalid domain", rule: policy.Rule{Protocol: "tcp", Domain: "*", Port: 443}},
		{name: "unterminated domain glob", rule: policy.Rule{Protocol: "tcp", Domain: "api[1.example.test", Port: 443}},
		{name: "empty domain glob", rule: policy.Rule{Protocol: "tcp", Domain: "api[!].example.test", Port: 443}},
		{name: "missing cidr", rule: policy.Rule{Protocol: "tcp", Port: 443}},
		{name: "invalid cidr", rule: policy.Rule{Protocol: "tcp", CIDR: "registry.example", Port: 443}},
		{name: "ambiguous mapped cidr", rule: policy.Rule{Protocol: "tcp", CIDR: "::ffff:0:0/95", Port: 443}},
		{name: "invalid protocol", rule: policy.Rule{Protocol: "icmp", CIDR: "192.0.2.1/32"}},
		{name: "ip literal as domain", rule: policy.Rule{Protocol: "tcp", Domain: "192.0.2.10", Port: 443}},
		{name: "unverified UDP domain", rule: policy.Rule{Protocol: "udp", Domain: "h3.example.test", Port: 443}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePolicy(policy.Policy{Allow: []policy.Rule{tt.rule}}, false); err == nil {
				t.Fatal("unsupported policy must be rejected")
			}
		})
	}
}

func TestIPv6HostForwardRequiresExplicitCapability(t *testing.T) {
	ports := []policy.Port{{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "::1"}}
	if err := validateIPv6PortCapability(ports, false); err == nil {
		t.Fatal("IPv6 host forward accepted while the capability is disabled")
	}
	if err := validateIPv6PortCapability(ports, true); err != nil {
		t.Fatalf("explicit IPv6 host forward rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Ports: ports}, "", false, false); err == nil {
		t.Fatal("disabled IPv6 host forward was rendered")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Ports: ports}, "", true, false); err != nil {
		t.Fatalf("explicit IPv6 host forward rejected: %v", err)
	}
}

func TestIPv6CIDRRuleRequiresExplicitCapability(t *testing.T) {
	rules := []policy.Rule{{Protocol: "tcp", CIDR: "2001:db8::/32", Port: 443}}
	if err := validateIPv6RuleCapability(rules, nil, false); err == nil {
		t.Fatal("IPv6 CIDR accepted while the capability is disabled")
	}
	if err := validateIPv6RuleCapability(rules, nil, true); err != nil {
		t.Fatalf("explicit IPv6 CIDR rejected: %v", err)
	}
	if err := validateIPv6RuleCapability([]policy.Rule{{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}}, nil, false); err != nil {
		t.Fatalf("IPv4 CIDR rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Allow: rules}, "", false, false); err == nil {
		t.Fatal("disabled IPv6 CIDR rule was rendered")
	}
	cfg, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(cfg), "2001:db8::/32") {
		t.Fatal("disabled IPv6 CIDR rule reached the gateway config")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Allow: rules}, "", true, false); err != nil {
		t.Fatalf("explicit IPv6 CIDR rule rejected: %v", err)
	}
	cfg, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `"2001:db8::/32"`) {
		t.Fatalf("IPv6 CIDR rule missing from config:\n%s", cfg)
	}
}

func TestValidatePolicyRejectsDomainDenyOverlappingIPAllow(t *testing.T) {
	p := policy.Policy{
		Allow: []policy.Rule{{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}},
		Deny:  []policy.Rule{{Protocol: "tcp", Domain: "blocked.example.test", Port: 443}},
	}
	if err := validatePolicy(p, false); err == nil {
		t.Fatal("overlapping domain deny and IP allow accepted")
	}
	p.Allow[0].Port = 8443
	if err := validatePolicy(p, false); err != nil {
		t.Fatalf("non-overlapping positive control rejected: %v", err)
	}
}

func TestDomainPolicyRenderAndUpstreamRequirement(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision: 4, SandboxID: "domains",
		Allow: []policy.Rule{{Protocol: "tcp", Domain: "*.example.com", Port: 443}},
	}, "1.1.1.1:53", false)
	if !strings.Contains(cfg, `domain: "*.example.com"`) {
		t.Fatalf("domain missing:\n%s", cfg)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "domains", Allow: []policy.Rule{{Protocol: "tcp", Domain: "example.com"}}}, "", false, false); err == nil {
		t.Fatal("domain policy without DNS upstream was accepted")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "domains", Allow: []policy.Rule{{Protocol: "tcp", Domain: "example.com"}}}, "1.1.1.1:53", false, false); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := New(Config{GVProxy: "/bin/true", RunDir: "/tmp/x"}); err != nil {
		t.Fatal(err)
	}
}

func TestStopUnknownIsSafe(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
}

func TestCloseRejectsNewStarts(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), policy.Policy{SandboxID: "dev"}); err == nil {
		t.Fatal("closed manager accepted a new gateway")
	}
}

func TestCloseReportsStartupInProgress(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reserveStart("dev"); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err == nil {
		t.Fatal("close reported success during gateway startup")
	}
}

func TestReloadWaitsForStartupBeforeFailingClosed(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reserveStart("dev"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Reload(context.Background(), policy.Policy{SandboxID: "dev"}) }()
	select {
	case <-done:
		t.Fatal("reload returned before startup completed")
	case <-time.After(50 * time.Millisecond):
	}
	m.mu.Lock()
	finished := m.starting["dev"]
	delete(m.starting, "dev")
	close(finished)
	m.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("reload reported success without a running gateway")
	}
}

func TestStartRejectsUnsafeSandboxID(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", ".", "..", "../outside", "a/b", `a\b`, "a\x00b", strings.Repeat("a", 64)} {
		t.Run(id, func(t *testing.T) {
			if _, err := m.Start(context.Background(), policy.Policy{SandboxID: id}); err == nil {
				t.Fatal("unsafe sandbox ID accepted")
			}
		})
	}
	for _, id := range []string{"dev", "DEV_1", "a.b-c"} {
		if !validSandboxID(id) {
			t.Fatalf("valid sandbox ID %q rejected", id)
		}
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gwtest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestStopUntrackedRemovesOwnSockets(t *testing.T) {
	dir := shortTempDir(t)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "dev.sock")
	apiSocket := filepath.Join(dir, "dev.api.sock")
	for _, path := range []string{socket, apiSocket} {
		conn, err := net.ListenPacket("unixgram", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Stop(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{socket, apiSocket} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
}

func TestStopUntrackedLeavesForeignSocket(t *testing.T) {
	runDir := shortTempDir(t)
	foreignDir := shortTempDir(t)
	foreign := filepath.Join(foreignDir, "dev.sock")
	conn, err := net.ListenPacket("unixgram", foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{GVProxy: "/bin/true", RunDir: runDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign socket changed: %v", err)
	}
}

func TestWatchReportsUnexpectedExitAndCleansSockets(t *testing.T) {
	dir := shortTempDir(t)
	exited := make(chan string, 1)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir, OnExit: func(name string) { exited <- name }})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 0") // #nosec G204 -- fixed test command
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	socket := filepath.Join(dir, "dev.sock")
	apiSocket := filepath.Join(dir, "dev.api.sock")
	for _, path := range []string{socket, apiSocket} {
		conn, err := net.ListenPacket("unixgram", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	proc := process{cmd: cmd, socket: socket, apiSocket: apiSocket, done: done}
	m.mu.Lock()
	m.procs["dev"] = proc
	m.mu.Unlock()
	m.watch("dev", proc, done)
	select {
	case name := <-exited:
		if name != "dev" {
			t.Fatalf("OnExit name = %q", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unexpected gateway exit was not reported")
	}
	m.mu.Lock()
	_, tracked := m.procs["dev"]
	m.mu.Unlock()
	if tracked {
		t.Fatal("exited gateway is still tracked")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gateway socket was not cleaned: %v", err)
	}
}

func TestWatchIgnoresOrderlyStop(t *testing.T) {
	dir := shortTempDir(t)
	exited := make(chan string, 1)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir, OnExit: func(name string) { exited <- name }})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 0") // #nosec G204 -- fixed test command
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	proc := process{cmd: cmd, socket: filepath.Join(dir, "dev.sock"), done: done, stopping: true}
	m.mu.Lock()
	m.procs["dev"] = proc
	m.mu.Unlock()
	m.watch("dev", proc, done)
	select {
	case name := <-exited:
		t.Fatalf("orderly stop reported as loss: %s", name)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestQUICDomainPolicyRequiresExplicitCapability(t *testing.T) {
	rule := policy.Rule{Protocol: "udp", Domain: "h3.example.test", Port: 443}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "quic", Allow: []policy.Rule{rule}}, "1.1.1.1:53", false, false); err == nil {
		t.Fatal("UDP domain rule accepted without the QUIC capability")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "quic", Allow: []policy.Rule{rule}}, "1.1.1.1:53", false, true); err != nil {
		t.Fatalf("explicit QUIC UDP domain rule rejected: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`protocol: "udp"`, `domain: "h3.example.test"`, `port: 443`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q in config:\n%s", want, data)
		}
	}
	manager, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir(), QUICEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.QUICEnabled() {
		t.Fatal("manager failed to report the explicit QUIC capability")
	}
	if err := manager.SetQUICEnabled(false); err != nil {
		t.Fatalf("disable QUIC before startup: %v", err)
	}
	if manager.QUICEnabled() {
		t.Fatal("QUIC capability stayed enabled after SetQUICEnabled(false)")
	}
}
