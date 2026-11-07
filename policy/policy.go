// Package policy defines the default-deny network policy model.
package policy

import (
	"errors"
	"net"
	"path"
	"strings"
)

// Action is an allow or deny decision.
type Action string

const (
	Allow       Action = "allow"
	Deny        Action = "deny"
	protocolTCP        = "tcp"
)

// Rule is a single policy rule.
type Rule struct {
	ID       string
	Action   Action
	Protocol string
	Domain   string
	CIDR     string
	Port     uint16
}

// Port maps a host loopback address/port to a guest port.
type Port struct {
	Host   uint16
	Guest  uint16
	Proto  string
	HostIP string
}

// Policy is the effective sandbox policy.
type Policy struct {
	Revision  int
	SandboxID string
	AuditPath string
	Allow     []Rule
	Deny      []Rule
	Ports     []Port
}

// Decision is the result of policy evaluation.
type Decision struct {
	Allow    bool
	RuleID   string
	Revision string
	Reason   string
}

// Request is a single network authorization request. Domain is used for a
// hostname target; Address is used for an IP target. HTTP fields are reserved
// for the HTTP policy phase.
type Request struct {
	Protocol string
	Address  string
	Domain   string
	Port     uint16
}

// Evaluate fails closed until a policy engine is configured.
func Evaluate(rule Rule) Decision {
	return Decision{Allow: false, RuleID: rule.ID, Reason: "policy engine unavailable"}
}

// Check evaluates compiled-in-command rules with deny precedence across both
// scopes. Domain rules are matched against Request.Domain; they never authorize
// an IP literal without a DNS binding.
func Check(allow, deny []Rule, req Request) Decision {
	if err := ValidateEnforcement(allow, deny); err != nil {
		return Decision{Allow: false, Reason: err.Error()}
	}
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = protocolTCP
	}
	for i := range deny {
		if ruleMatches(deny[i], protocol, req) {
			return Decision{Allow: false, RuleID: deny[i].ID, Reason: "deny rule " + target(deny[i])}
		}
	}
	for i := range allow {
		if ruleMatches(allow[i], protocol, req) {
			return Decision{Allow: true, RuleID: allow[i].ID, Reason: "allow rule " + target(allow[i])}
		}
	}
	return Decision{Allow: false, Reason: "default deny"}
}

// ValidateEnforcement rejects combinations the current gateway cannot enforce.
func ValidateEnforcement(allow, deny []Rule) error {
	for _, rules := range [][]Rule{allow, deny} {
		for _, rule := range rules {
			if err := validateEnforcementRule(rule); err != nil {
				return err
			}
		}
	}
	for _, denied := range deny {
		if denied.Domain == "" {
			continue
		}
		for _, granted := range allow {
			if domainDenyConflictsWithIPAllow(denied, granted) {
				return errors.New("domain deny conflicts with direct IP allow; enforcement unsupported")
			}
		}
	}
	return nil
}

func validateEnforcementRule(rule Rule) error {
	if rule.Domain == "" {
		return nil
	}
	if net.ParseIP(strings.TrimSpace(rule.Domain)) != nil {
		return errors.New("domain rule must not be an IP literal; use a CIDR rule")
	}
	return nil
}

func domainDenyConflictsWithIPAllow(denied, granted Rule) bool {
	return granted.CIDR != "" &&
		normalizedProtocol(granted.Protocol) == normalizedProtocol(denied.Protocol) &&
		(granted.Port == 0 || denied.Port == 0 || granted.Port == denied.Port)
}

func normalizedProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return protocolTCP
	}
	return protocol
}

func target(rule Rule) string {
	if rule.Domain != "" {
		return rule.Domain
	}
	return rule.CIDR
}

func ruleMatches(rule Rule, protocol string, req Request) bool {
	ruleProtocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if ruleProtocol == "" {
		ruleProtocol = protocolTCP
	}
	if ruleProtocol != protocol {
		return false
	}
	if rule.Port != 0 && rule.Port != req.Port {
		return false
	}
	if rule.Domain != "" {
		return req.Domain != "" && domainMatches(rule.Domain, req.Domain)
	}
	if req.Address == "" || rule.CIDR == "" {
		return false
	}
	ip := net.ParseIP(req.Address)
	_, network, err := net.ParseCIDR(rule.CIDR)
	return err == nil && ip != nil && network.Contains(ip)
}

func domainMatches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case strings.HasPrefix(pattern, "**."):
		return wildcardSuffixMatches(pattern[3:], name, false)
	case strings.HasPrefix(pattern, "*."):
		return wildcardSuffixMatches(pattern[2:], name, true)
	}
	patternLabels := strings.Split(pattern, ".")
	nameLabels := strings.Split(name, ".")
	if len(patternLabels) != len(nameLabels) {
		return false
	}
	for i := range patternLabels {
		glob := strings.ReplaceAll(patternLabels[i], "[!", "[^")
		ok, err := path.Match(glob, nameLabels[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

func wildcardSuffixMatches(pattern, name string, single bool) bool {
	suffixLabels := strings.Split(pattern, ".")
	labels := strings.Split(name, ".")
	extra := len(labels) - len(suffixLabels)
	if extra < 1 || (single && extra != 1) {
		return false
	}
	for _, label := range labels[:extra] {
		if label == "" {
			return false
		}
	}
	return domainMatches(pattern, strings.Join(labels[extra:], "."))
}
