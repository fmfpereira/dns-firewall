package firewall

import (
	"errors"
	"reflect"
	"testing"

	"dns-firewall/internal/dns"
)

func TestDesiredSourcesNormalizesHostPrefixes(t *testing.T) {
	addresses := []dns.AllowedAddress{
		{Family: dns.IPv4, Value: "192.0.2.10"},
		{Family: dns.IPv4, Value: "198.51.100.7/32"},
		{Family: dns.IPv4, Value: "192.0.2.0/24"},
		{Family: dns.IPv6, Value: "2001:db8::1"},
	}

	got := desiredSources(dns.IPv4, addresses)
	want := []string{"192.0.2.0/24", "192.0.2.10", "198.51.100.7"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSourceDiff(t *testing.T) {
	added, removed := sourceDiff(
		[]string{"192.0.2.10", "198.51.100.1"},
		[]string{"192.0.2.10", "203.0.113.5"},
	)

	if !reflect.DeepEqual(added, []string{"203.0.113.5"}) {
		t.Fatalf("added got %v", added)
	}
	if !reflect.DeepEqual(removed, []string{"198.51.100.1"}) {
		t.Fatalf("removed got %v", removed)
	}
}

func TestIptablesErrorClassification(t *testing.T) {
	alreadyExists := commandError{output: "iptables: Chain already exists.\n", err: errors.New("exit status 1")}
	if !isAlreadyExists(alreadyExists) {
		t.Fatal("expected chain already exists error to be classified")
	}

	missingRule := commandError{output: "iptables: Bad rule (does a matching rule exist in that chain?).\n", err: errors.New("exit status 1")}
	if !isRuleMissing(missingRule) {
		t.Fatal("expected missing rule error to be classified")
	}

	permissionDenied := commandError{output: "iptables: Permission denied (you must be root).\n", err: errors.New("exit status 4")}
	if isRuleMissing(permissionDenied) {
		t.Fatal("permission denied must not be classified as a missing rule")
	}
}

func TestRestoreInput(t *testing.T) {
	got := restoreInput("DNS_FIREWALL_ALLOW", []string{"192.0.2.10", "198.51.100.0/24"})
	want := "*filter\n" +
		"-F DNS_FIREWALL_ALLOW\n" +
		"-A DNS_FIREWALL_ALLOW -s 192.0.2.10 -j ACCEPT\n" +
		"-A DNS_FIREWALL_ALLOW -s 198.51.100.0/24 -j ACCEPT\n" +
		"COMMIT\n"

	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRestoreBinaryFor(t *testing.T) {
	tests := map[string]string{
		"iptables":  "iptables-restore",
		"ip6tables": "ip6tables-restore",
	}

	for input, want := range tests {
		if got := restoreBinaryFor(input); got != want {
			t.Fatalf("restoreBinaryFor(%q) = %q, want %q", input, got, want)
		}
	}
}
