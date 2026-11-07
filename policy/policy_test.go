package policy

import "testing"

func TestDefaultDeny(t *testing.T) {
	for _, action := range []Action{"", Allow, Deny} {
		got := Evaluate(Rule{ID: "fixture", Action: action})
		if got.Allow {
			t.Fatalf("unconfigured engine allowed action %q", action)
		}
	}
}

func TestCheckDenyWinsAndDomainRulesDoNotAuthorizeIP(t *testing.T) {
	allow := []Rule{
		{ID: "domain", Protocol: "tcp", Domain: "*.example.com", Port: 443},
		{ID: "cidr", Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 8443},
	}
	deny := []Rule{{ID: "deny", Protocol: "tcp", Domain: "secret.example.com", Port: 443}}
	if got := Check(allow, deny, Request{Protocol: "tcp", Domain: "api.example.com", Port: 443}); !got.Allow || got.RuleID != "domain" {
		t.Fatalf("allow=%+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Domain: "secret.example.com", Port: 443}); got.Allow || got.RuleID != "deny" {
		t.Fatalf("deny=%+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Address: "10.1.2.3", Port: 8443}); !got.Allow || got.RuleID != "cidr" {
		t.Fatalf("cidr=%+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Address: "203.0.113.4", Port: 443}); got.Allow {
		t.Fatalf("domain rule authorized IP: %+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Address: "10.1.2.3", Port: 80}); got.Allow {
		t.Fatalf("port mismatch: %+v", got)
	}
}

func TestUnsupportedDomainConfigurationsFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		allow []Rule
		deny  []Rule
	}{
		{"overlapping CIDR and domain deny", []Rule{{Protocol: "tcp", CIDR: "0.0.0.0/0"}}, []Rule{{Protocol: "tcp", Domain: "secret.example.test", Port: 443}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEnforcement(tt.allow, tt.deny); err == nil {
				t.Fatal("unsupported policy accepted")
			}
			if got := Check(tt.allow, tt.deny, Request{Protocol: "tcp", Domain: "api.example.test", Port: 443}); got.Allow {
				t.Fatalf("unsupported policy reported an allow: %+v", got)
			}
		})
	}
	allowed := []Rule{{ID: "ok", Protocol: "tcp", Domain: "api.example.test", Port: 443}}
	if err := ValidateEnforcement(allowed, nil); err != nil {
		t.Fatal(err)
	}
	if got := Check(allowed, nil, Request{Protocol: "tcp", Domain: "api.example.test", Port: 443}); !got.Allow {
		t.Fatalf("supported positive control denied: %+v", got)
	}
}

func TestUDPDomainPolicyAllowsOnlyMatchingQUICSNI(t *testing.T) {
	allow := []Rule{{ID: "h3", Protocol: "udp", Domain: "h3.example.test", Port: 18443}}
	deny := []Rule{{ID: "wrong-h3", Protocol: "udp", Domain: "blocked.example.test", Port: 18443}}
	if err := ValidateEnforcement(allow, deny); err != nil {
		t.Fatalf("valid UDP domain policy rejected: %v", err)
	}
	if got := Check(allow, deny, Request{Protocol: "udp", Domain: "h3.example.test", Port: 18443}); !got.Allow || got.RuleID != "h3" {
		t.Fatalf("QUIC positive control denied: %+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "udp", Domain: "other.example.test", Port: 18443}); got.Allow {
		t.Fatalf("wrong SNI was allowed: %+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "udp", Domain: "blocked.example.test", Port: 18443}); got.Allow || got.RuleID != "wrong-h3" {
		t.Fatalf("QUIC domain deny did not win: %+v", got)
	}
}

func TestDomainGlobLabelBoundaries(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"api?.example.test", "api1.example.test", true},
		{"api?.example.test", "api.example.test", false},
		{"api?.example.test", "api12.example.test", false},
		{"api[!1].example.test", "api2.example.test", true},
		{"api[!1].example.test", "api1.example.test", false},
		{"api[!1]example.test", "api.example.test", false},
		{"*.example.test", "a.example.test", true},
		{"*.example.test", "a.b.example.test", false},
		{"*.api?.example.test", "www.api1.example.test", true},
		{"*.api?.example.test", "www.api.example.test", false},
		{"**.example.test", "a..example.test", false},
	}
	for _, tt := range tests {
		if got := domainMatches(tt.pattern, tt.name); got != tt.want {
			t.Errorf("domainMatches(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func FuzzDomainMatches(f *testing.F) {
	f.Add("api?.example.test", "api1.example.test")
	f.Add("api[!1].example.test", "api2.example.test")
	f.Add("*.example.test", "host.example.test")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		if len(pattern) > 253 || len(name) > 253 {
			t.Skip()
		}
		_ = domainMatches(pattern, name)
	})
}
