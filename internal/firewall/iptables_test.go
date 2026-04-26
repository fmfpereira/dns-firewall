package firewall

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"dns-firewall/internal/config"
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
		"-A DNS_FIREWALL_ALLOW -s 192.0.2.10 -j RETURN\n" +
		"-A DNS_FIREWALL_ALLOW -s 198.51.100.0/24 -j RETURN\n" +
		"-A DNS_FIREWALL_ALLOW -j DROP\n" +
		"COMMIT\n"

	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestManagedChainStateRequiresReturnAndTerminalDrop(t *testing.T) {
	output := "-A DNS_FIREWALL_ALLOW -s 192.0.2.10 -j RETURN\n" +
		"-A DNS_FIREWALL_ALLOW -s 198.51.100.0/24 -j ACCEPT\n" +
		"-A DNS_FIREWALL_ALLOW -j DROP\n"

	state := managedChainState(output, "DNS_FIREWALL_ALLOW")
	want := []string{"192.0.2.10"}
	if !reflect.DeepEqual(state.sources, want) {
		t.Fatalf("sources got %v, want %v", state.sources, want)
	}
	if !state.terminalDrop {
		t.Fatal("expected terminal drop")
	}
}

func TestDesiredJumpSpecsAreInterfaceScoped(t *testing.T) {
	got := desiredJumpSpecs("DNS_FIREWALL_ALLOW", []string{"eth0", "ppp0"})
	want := [][]string{
		{"-i", "eth0", "-j", "DNS_FIREWALL_ALLOW"},
		{"-i", "ppp0", "-j", "DNS_FIREWALL_ALLOW"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseDefaultRouteInterfaces(t *testing.T) {
	output := "default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100\n" +
		"default via 198.51.100.1 dev ppp0 metric 200\n"

	got := parseDefaultRouteInterfaces(output)
	want := []string{"eth0", "ppp0"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseDefaultRouteInterfacesHandlesMultipath(t *testing.T) {
	output := "default proto static metric 100 " +
		"nexthop via 192.0.2.1 dev eth0 weight 1 " +
		"nexthop via 198.51.100.1 dev eth1 weight 1\n"

	got := parseDefaultRouteInterfaces(output)
	want := []string{"eth0", "eth1"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseDefaultRouteInterfacesReturnsEmptyWithoutDefault(t *testing.T) {
	output := "192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.10\n"

	got := parseDefaultRouteInterfaces(output)
	if len(got) != 0 {
		t.Fatalf("got %v, want no interfaces", got)
	}
}

func TestDedupeStringsPreservesOrder(t *testing.T) {
	got := dedupeStrings([]string{"eth0", "ppp0", "eth0"})
	want := []string{"eth0", "ppp0"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFirstRulesMatch(t *testing.T) {
	rules := [][]string{
		{"-i", "eth0", "-j", "DNS_FIREWALL_ALLOW"},
		{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
	}
	desired := [][]string{{"-i", "eth0", "-j", "DNS_FIREWALL_ALLOW"}}

	if !firstRulesMatch(rules, desired) {
		t.Fatal("expected desired managed jump to be first")
	}
	if firstRulesMatch(rules[1:], desired) {
		t.Fatal("expected non-leading managed jump to fail")
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

func TestRestoreArgsWaitForXtablesLock(t *testing.T) {
	got := restoreArgs()
	want := []string{"--wait", "--noflush"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

type fakeIptables struct {
	rules [][]string
	calls [][]string
}

func (f *fakeIptables) commandFn(_ context.Context, binary string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{binary}, args...))

	i := 0
	if i < len(args) && args[i] == "-w" {
		i++
	}
	if i >= len(args) {
		return "", nil
	}

	switch args[i] {
	case "-S":
		return f.dump(), nil
	case "-I":
		if i+3 > len(args) {
			return "", nil
		}
		pos, _ := strconv.Atoi(args[i+2])
		spec := append([]string(nil), args[i+3:]...)
		idx := pos - 1
		if idx < 0 {
			idx = 0
		}
		if idx > len(f.rules) {
			idx = len(f.rules)
		}
		updated := make([][]string, 0, len(f.rules)+1)
		updated = append(updated, f.rules[:idx]...)
		updated = append(updated, spec)
		updated = append(updated, f.rules[idx:]...)
		f.rules = updated
		return "", nil
	case "-D":
		if i+2 > len(args) {
			return "", nil
		}
		spec := args[i+2:]
		for j, rule := range f.rules {
			if reflect.DeepEqual(rule, spec) {
				f.rules = append(f.rules[:j], f.rules[j+1:]...)
				return "", nil
			}
		}
		return "", commandError{
			binary: binary,
			args:   append([]string(nil), args...),
			output: "iptables: Bad rule (does a matching rule exist in that chain?).",
			err:    errors.New("exit status 1"),
		}
	}
	return "", nil
}

func (f *fakeIptables) dump() string {
	var b strings.Builder
	for _, rule := range f.rules {
		b.WriteString("-A INPUT")
		for _, field := range rule {
			b.WriteString(" ")
			b.WriteString(field)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func newTestManager(fake *fakeIptables) *Manager {
	return &Manager{
		config:    config.FirewallConfig{Chain: "DNS_FW"},
		commandFn: fake.commandFn,
	}
}

func TestEnsureJumpsFreshInstall(t *testing.T) {
	fake := &fakeIptables{}
	mgr := newTestManager(fake)

	if err := mgr.ensureJumps(context.Background(), "iptables", []string{"eth0"}); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"-i", "eth0", "-j", "DNS_FW"}}
	if !reflect.DeepEqual(fake.rules, want) {
		t.Fatalf("rules got %v, want %v", fake.rules, want)
	}
}

func TestApplyDryRunDoesNotRequireManagedChainToExist(t *testing.T) {
	fake := &fakeIptables{}
	mgr := &Manager{
		config:    config.FirewallConfig{Chain: "DNS_FW", Interfaces: []string{"eth0"}},
		dryRun:    true,
		commandFn: fake.commandFn,
	}

	err := mgr.Apply(context.Background(), []dns.AllowedAddress{
		{Family: dns.IPv4, Value: "192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, call := range fake.calls {
		for i, arg := range call {
			if arg == "-S" && i+1 < len(call) && call[i+1] == "DNS_FW" {
				t.Fatalf("dry-run should not require managed chain state, got call %v", call)
			}
		}
	}
}

func TestEnsureJumpsAlreadyInSyncNoop(t *testing.T) {
	fake := &fakeIptables{
		rules: [][]string{{"-i", "eth0", "-j", "DNS_FW"}},
	}
	mgr := newTestManager(fake)

	if err := mgr.ensureJumps(context.Background(), "iptables", []string{"eth0"}); err != nil {
		t.Fatal(err)
	}

	for _, call := range fake.calls {
		for _, arg := range call {
			if arg == "-I" || arg == "-D" {
				t.Fatalf("expected only reads, got call %v", call)
			}
		}
	}
}

func TestEnsureJumpsInsertsBeforeRemovingStale(t *testing.T) {
	fake := &fakeIptables{
		rules: [][]string{{"-i", "ppp0", "-j", "DNS_FW"}},
	}
	mgr := newTestManager(fake)

	if err := mgr.ensureJumps(context.Background(), "iptables", []string{"eth0"}); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"-i", "eth0", "-j", "DNS_FW"}}
	if !reflect.DeepEqual(fake.rules, want) {
		t.Fatalf("rules got %v, want %v", fake.rules, want)
	}

	var firstWriteOp string
	for _, call := range fake.calls {
		for _, arg := range call {
			if arg == "-I" || arg == "-D" {
				firstWriteOp = arg
				break
			}
		}
		if firstWriteOp != "" {
			break
		}
	}
	if firstWriteOp != "-I" {
		t.Fatalf("first write op was %q; expected insert before delete to avoid ungated window", firstWriteOp)
	}
}

func TestEnsureJumpsLeavesUserJumpAlone(t *testing.T) {
	userJump := []string{"-p", "tcp", "--dport", "22", "-j", "DNS_FW"}
	fake := &fakeIptables{
		rules: [][]string{userJump},
	}
	mgr := newTestManager(fake)

	if err := mgr.ensureJumps(context.Background(), "iptables", []string{"eth0"}); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"-i", "eth0", "-j", "DNS_FW"},
		userJump,
	}
	if !reflect.DeepEqual(fake.rules, want) {
		t.Fatalf("rules got %v, want %v", fake.rules, want)
	}
}

func TestIsManagedJumpRecognizesLegacyAndCurrentForms(t *testing.T) {
	cases := map[string]struct {
		rule []string
		want bool
	}{
		"current form":                        {[]string{"-i", "eth0", "-j", "DNS_FW"}, true},
		"legacy form":                         {[]string{"-j", "DNS_FW"}, true},
		"user with extra":                     {[]string{"-p", "tcp", "--dport", "22", "-j", "DNS_FW"}, false},
		"different chain":                     {[]string{"-i", "eth0", "-j", "OTHER"}, false},
		"jump to our chain with output iface": {[]string{"-o", "eth0", "-j", "DNS_FW"}, false},
	}
	for name, tc := range cases {
		if got := isManagedJump(tc.rule, "DNS_FW"); got != tc.want {
			t.Fatalf("%s: isManagedJump(%v) = %v, want %v", name, tc.rule, got, tc.want)
		}
	}
}
