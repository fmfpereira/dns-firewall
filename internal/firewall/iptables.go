package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"dns-firewall/internal/config"
	"dns-firewall/internal/dns"
)

type commandError struct {
	binary string
	args   []string
	output string
	err    error
}

type Manager struct {
	config    config.FirewallConfig
	dryRun    bool
	commandFn func(ctx context.Context, binary string, args ...string) (string, error)
	restoreFn func(ctx context.Context, binary string, payload string) error
}

const (
	inputChain     = "INPUT"
	insertPosition = 1
)

func (m *Manager) attachChains() []string {
	chains := []string{inputChain}
	chains = append(chains, m.config.ExtraAttachChains...)
	return chains
}

func NewManager(cfg config.FirewallConfig, dryRun bool) *Manager {
	return &Manager{config: cfg, dryRun: dryRun}
}

func (m *Manager) Apply(ctx context.Context, addresses []dns.AllowedAddress) error {
	if len(addresses) == 0 {
		slog.Warn("refusing to apply empty allowlist; keeping existing firewall rules")
		return nil
	}
	if err := m.applyFamily(ctx, "iptables", dns.IPv4, addresses); err != nil {
		return err
	}
	if err := m.applyFamily(ctx, "ip6tables", dns.IPv6, addresses); err != nil {
		return err
	}
	return nil
}

func (m *Manager) applyFamily(ctx context.Context, binary string, family dns.Family, addresses []dns.AllowedAddress) error {
	interfaces, err := m.effectiveInterfaces(ctx, family)
	if err != nil {
		return err
	}
	if len(interfaces) == 0 {
		markNoDefaultRoute(binary, family)
		return m.removeManagedJumps(ctx, binary)
	}
	clearNoDefaultRoute(binary, family)

	if err := m.ensureChain(ctx, binary); err != nil {
		return err
	}
	if err := m.ensureJumps(ctx, binary, interfaces); err != nil {
		return err
	}

	desired := desiredSources(family, addresses)
	if m.dryRun {
		slog.Info("dry-run firewall update planned", "binary", binary, "chain", m.config.Chain, "desired_rules", len(desired))
		return m.restoreRules(ctx, binary, desired)
	}

	state, err := m.currentState(ctx, binary)
	if err != nil {
		return err
	}
	added, removed := sourceDiff(state.sources, desired)
	expectedRules := 2 + len(desired) + 1
	if len(added) == 0 && len(removed) == 0 && state.canonicalShape {
		slog.Info("firewall already in sync", "binary", binary, "chain", m.config.Chain, "rules", len(desired))
		return nil
	}
	if !state.canonicalShape {
		slog.Info(
			"rewriting managed chain to canonical layout",
			"binary", binary,
			"chain", m.config.Chain,
			"conntrack_return", state.conntrackReturn,
			"invalid_drop", state.invalidDrop,
			"terminal_drop", state.terminalDrop,
			"current_total_rules", state.totalRules,
			"expected_total_rules", expectedRules,
		)
	}
	slog.Info(
		"firewall change detected",
		"binary", binary,
		"chain", m.config.Chain,
		"desired_rules", len(desired),
		"current_rules", len(state.sources),
		"current_total_rules", state.totalRules,
		"canonical_shape", state.canonicalShape,
		"terminal_drop", state.terminalDrop,
		"conntrack_return", state.conntrackReturn,
		"invalid_drop", state.invalidDrop,
		"added", len(added),
		"removed", len(removed),
	)
	slog.Debug("firewall rule diff", "binary", binary, "added", added, "removed", removed)

	if err := m.restoreRules(ctx, binary, desired); err != nil {
		return err
	}
	slog.Info("firewall rules updated", "binary", binary, "chain", m.config.Chain, "rules", len(desired))
	return nil
}

var (
	noRouteStateMu sync.Mutex
	noRouteState   = map[string]bool{}

	missingChainStateMu sync.Mutex
	missingChainState   = map[string]bool{}
)

func markNoDefaultRoute(binary string, family dns.Family) {
	noRouteStateMu.Lock()
	defer noRouteStateMu.Unlock()
	if noRouteState[binary] {
		slog.Debug("no default-route interface still missing", "binary", binary, "family", family)
		return
	}
	noRouteState[binary] = true
	slog.Warn("no default-route interface found; removing managed jumps for firewall family", "binary", binary, "family", family)
}

func clearNoDefaultRoute(binary string, family dns.Family) {
	noRouteStateMu.Lock()
	defer noRouteStateMu.Unlock()
	if !noRouteState[binary] {
		return
	}
	delete(noRouteState, binary)
	slog.Info("default-route interface restored", "binary", binary, "family", family)
}

func markChainMissing(binary, chain string) {
	key := binary + "/" + chain
	missingChainStateMu.Lock()
	defer missingChainStateMu.Unlock()
	if missingChainState[key] {
		slog.Debug("extra attach chain still missing", "binary", binary, "attach_chain", chain)
		return
	}
	missingChainState[key] = true
	slog.Warn("extra attach chain not found; skipping", "binary", binary, "attach_chain", chain)
}

func clearChainMissing(binary, chain string) {
	key := binary + "/" + chain
	missingChainStateMu.Lock()
	defer missingChainStateMu.Unlock()
	if !missingChainState[key] {
		return
	}
	delete(missingChainState, key)
	slog.Info("extra attach chain found", "binary", binary, "attach_chain", chain)
}

func (m *Manager) effectiveInterfaces(ctx context.Context, family dns.Family) ([]string, error) {
	if len(m.config.Interfaces) > 0 {
		return dedupeStrings(m.config.Interfaces), nil
	}
	interfaces, err := defaultRouteInterfaces(ctx, family)
	if err != nil {
		slog.Error("failed to detect default-route interface", "family", family, "error", err)
		return nil, err
	}
	slog.Info("default-route interfaces detected", "family", family, "interfaces", interfaces)
	return interfaces, nil
}

func (m *Manager) ensureChain(ctx context.Context, binary string) error {
	_, err := m.command(ctx, binary, "-w", "-N", m.config.Chain)
	if err == nil || isAlreadyExists(err) {
		if err == nil {
			slog.Info("firewall managed chain created", "binary", binary, "chain", m.config.Chain)
		}
		return nil
	}
	slog.Error("failed to create firewall managed chain", "binary", binary, "chain", m.config.Chain, "error", err)
	return err
}

func (m *Manager) ensureJumps(ctx context.Context, binary string, interfaces []string) error {
	for _, chain := range m.attachChains() {
		if err := m.ensureJumpsForChain(ctx, binary, chain, interfaces); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ensureJumpsForChain(ctx context.Context, binary, chain string, interfaces []string) error {
	desired := desiredJumpSpecs(m.config.Chain, interfaces)
	rules, err := m.attachChainRules(ctx, binary, chain)
	if err != nil {
		if chain != inputChain && isMissingChain(err) {
			markChainMissing(binary, chain)
			return nil
		}
		return err
	}
	if chain != inputChain {
		clearChainMissing(binary, chain)
	}

	if firstRulesMatch(rules, desired) {
		return m.removeStaleJumps(ctx, binary, chain, rules[len(desired):], nil)
	}

	for i, spec := range desired {
		args := append([]string{"-w", "-I", chain, strconv.Itoa(insertPosition + i)}, spec...)
		slog.Info("inserting firewall managed chain jump", "binary", binary, "attach_chain", chain, "chain", m.config.Chain, "position", insertPosition+i, "rule", spec)
		if err := m.run(ctx, binary, args...); err != nil {
			return err
		}
	}

	postInsertRules, err := m.attachChainRules(ctx, binary, chain)
	if err != nil {
		return err
	}
	if len(postInsertRules) <= len(desired) {
		return nil
	}
	return m.removeStaleJumps(ctx, binary, chain, postInsertRules[len(desired):], nil)
}

func (m *Manager) run(ctx context.Context, binary string, args ...string) error {
	if m.dryRun {
		slog.Info("dry-run firewall command", "command", append([]string{binary}, args...))
		return nil
	}

	output, err := m.exec(ctx, binary, args...)
	if err != nil {
		slog.Error("firewall command failed", "binary", binary, "args", args, "output", strings.TrimSpace(output), "error", err)
		return err
	}
	return nil
}

func (m *Manager) attachChainRules(ctx context.Context, binary, chain string) ([][]string, error) {
	args := []string{"-w", "-S", chain}
	output, err := m.exec(ctx, binary, args...)
	if err != nil {
		if !isMissingChain(err) {
			slog.Error("firewall command failed", "binary", binary, "args", args, "output", strings.TrimSpace(output), "error", err)
		}
		return nil, err
	}
	return parseChainRules(output, chain), nil
}

func (m *Manager) removeStaleJumps(ctx context.Context, binary, chain string, rules [][]string, desired [][]string) error {
	for _, rule := range rules {
		if !isManagedJump(rule, m.config.Chain) || containsRule(desired, rule) {
			continue
		}
		args := append([]string{"-w", "-D", chain}, rule...)
		slog.Info("removing stale firewall managed chain jump", "binary", binary, "attach_chain", chain, "chain", m.config.Chain, "rule", rule)
		if err := m.run(ctx, binary, args...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeManagedJumps(ctx context.Context, binary string) error {
	for _, chain := range m.attachChains() {
		rules, err := m.attachChainRules(ctx, binary, chain)
		if err != nil {
			if chain != inputChain && isMissingChain(err) {
				continue
			}
			return err
		}
		if err := m.removeStaleJumps(ctx, binary, chain, rules, nil); err != nil {
			return err
		}
	}
	return m.flushManagedChain(ctx, binary)
}

func (m *Manager) flushManagedChain(ctx context.Context, binary string) error {
	_, err := m.command(ctx, binary, "-w", "-F", m.config.Chain)
	if err == nil || isMissingChain(err) {
		return nil
	}
	slog.Error("failed to flush managed chain", "binary", binary, "chain", m.config.Chain, "error", err)
	return err
}

type chainState struct {
	sources         []string
	totalRules      int
	terminalDrop    bool
	conntrackReturn bool
	invalidDrop     bool
	canonicalShape  bool
}

var (
	conntrackReturnStates = []string{"ESTABLISHED", "RELATED"}
	invalidDropStates     = []string{"INVALID"}
)

func (m *Manager) currentState(ctx context.Context, binary string) (chainState, error) {
	output, err := m.output(ctx, binary, "-w", "-S", m.config.Chain)
	if err != nil {
		return chainState{}, err
	}
	return managedChainState(output, m.config.Chain), nil
}

func managedChainState(output string, chain string) chainState {
	seen := map[string]struct{}{}
	rules := parseChainRules(output, chain)
	for _, fields := range rules {
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "-s" {
				continue
			}
			if !ruleJumpsTo(fields, "RETURN") {
				continue
			}
			source := normalizeSource(fields[i+1])
			if source != "" {
				seen[source] = struct{}{}
			}
		}
	}
	sources := sortedKeys(seen)
	return chainState{
		sources:         sources,
		totalRules:      len(rules),
		terminalDrop:    len(rules) > 0 && ruleEquals(rules[len(rules)-1], []string{"-j", "DROP"}),
		conntrackReturn: len(rules) > 0 && matchesConntrackRule(rules[0], conntrackReturnStates, "RETURN"),
		invalidDrop:     len(rules) > 1 && matchesConntrackRule(rules[1], invalidDropStates, "DROP"),
		canonicalShape:  chainHasCanonicalShape(rules, sources),
	}
}

func canonicalChainRules(sources []string) [][]string {
	rules := make([][]string, 0, len(sources)+3)
	rules = append(rules, []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"})
	rules = append(rules, []string{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"})
	for _, source := range sources {
		rules = append(rules, []string{"-s", source, "-j", "RETURN"})
	}
	rules = append(rules, []string{"-j", "DROP"})
	return rules
}

func chainHasCanonicalShape(rules [][]string, sources []string) bool {
	expected := canonicalChainRules(sources)
	if len(rules) != len(expected) {
		return false
	}
	if !matchesConntrackRule(rules[0], conntrackReturnStates, "RETURN") {
		return false
	}
	if !matchesConntrackRule(rules[1], invalidDropStates, "DROP") {
		return false
	}
	for i := 2; i < len(rules); i++ {
		if !ruleEquals(rules[i], expected[i]) {
			return false
		}
	}
	return true
}

func matchesConntrackRule(fields []string, wantStates []string, wantTarget string) bool {
	if len(fields) != 6 {
		return false
	}
	if fields[0] != "-m" || fields[1] != "conntrack" || fields[2] != "--ctstate" {
		return false
	}
	if fields[4] != "-j" || fields[5] != wantTarget {
		return false
	}
	got := strings.Split(fields[3], ",")
	if len(got) != len(wantStates) {
		return false
	}
	gotSet := toSet(got)
	for _, state := range wantStates {
		if _, ok := gotSet[state]; !ok {
			return false
		}
	}
	return true
}

func (m *Manager) output(ctx context.Context, binary string, args ...string) (string, error) {
	output, err := m.exec(ctx, binary, args...)
	if err != nil {
		slog.Error("firewall command failed", "binary", binary, "args", args, "output", strings.TrimSpace(output), "error", err)
		return "", err
	}
	return output, nil
}

func (m *Manager) restoreRules(ctx context.Context, binary string, sources []string) error {
	payload := restoreInput(m.config.Chain, sources)
	restoreBinary := restoreBinaryFor(binary)
	restoreArgs := restoreArgs()
	if m.dryRun {
		slog.Info("dry-run firewall restore command", "command", append([]string{restoreBinary}, restoreArgs...), "input", payload)
		return nil
	}
	if m.restoreFn != nil {
		return m.restoreFn(ctx, restoreBinary, payload)
	}

	cmd := exec.CommandContext(ctx, restoreBinary, restoreArgs...)
	cmd.Stdin = strings.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		commandErr := commandError{
			binary: restoreBinary,
			args:   restoreArgs,
			output: string(output),
			err:    err,
		}
		slog.Error("firewall restore command failed", "binary", restoreBinary, "output", strings.TrimSpace(string(output)), "error", commandErr)
		return commandErr
	}
	return nil
}

func (m *Manager) command(ctx context.Context, binary string, args ...string) (string, error) {
	if m.dryRun {
		slog.Info("dry-run firewall command", "command", append([]string{binary}, args...))
		return "", nil
	}
	return m.exec(ctx, binary, args...)
}

func (m *Manager) exec(ctx context.Context, binary string, args ...string) (string, error) {
	if m.commandFn != nil {
		return m.commandFn(ctx, binary, args...)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), commandError{
			binary: binary,
			args:   append([]string(nil), args...),
			output: string(output),
			err:    err,
		}
	}
	return string(output), nil
}

func restoreBinaryFor(binary string) string {
	switch binary {
	case "iptables":
		return "iptables-restore"
	case "ip6tables":
		return "ip6tables-restore"
	default:
		return binary + "-restore"
	}
}

func restoreArgs() []string {
	return []string{"--wait", "--noflush"}
}

func defaultRouteInterfaces(ctx context.Context, family dns.Family) ([]string, error) {
	ipFamily := "-4"
	if family == dns.IPv6 {
		ipFamily = "-6"
	}

	cmd := exec.CommandContext(ctx, "ip", ipFamily, "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, commandError{
			binary: "ip",
			args:   []string{ipFamily, "route", "show", "default"},
			output: string(output),
			err:    err,
		}
	}
	return parseDefaultRouteInterfaces(string(output)), nil
}

func parseDefaultRouteInterfaces(output string) []string {
	interfaces := make([]string, 0)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "dev" {
				continue
			}
			iface := fields[i+1]
			if _, ok := seen[iface]; ok {
				continue
			}
			seen[iface] = struct{}{}
			interfaces = append(interfaces, iface)
		}
	}
	return interfaces
}

func restoreInput(chain string, sources []string) string {
	var builder strings.Builder
	builder.WriteString("*filter\n")
	builder.WriteString("-F ")
	builder.WriteString(chain)
	builder.WriteByte('\n')
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n")
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -m conntrack --ctstate INVALID -j DROP\n")
	for _, source := range sources {
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -s ")
		builder.WriteString(source)
		builder.WriteString(" -j RETURN\n")
	}
	builder.WriteString("-A ")
	builder.WriteString(chain)
	builder.WriteString(" -j DROP\n")
	builder.WriteString("COMMIT\n")
	return builder.String()
}

func (e commandError) Error() string {
	return fmt.Sprintf("%s %v failed: %s: %v", e.binary, e.args, strings.TrimSpace(e.output), e.err)
}

func (e commandError) Unwrap() error {
	return e.err
}

func isAlreadyExists(err error) bool {
	var commandErr commandError
	text := err.Error()
	if errors.As(err, &commandErr) {
		text = commandErr.output
	}
	return strings.Contains(text, "Chain already exists") || strings.Contains(text, "File exists")
}

func isRuleMissing(err error) bool {
	var commandErr commandError
	text := err.Error()
	if errors.As(err, &commandErr) {
		text = commandErr.output
	}
	return strings.Contains(text, "Bad rule") ||
		strings.Contains(text, "does a matching rule exist") ||
		strings.Contains(text, "No chain/target/match by that name")
}

func isMissingChain(err error) bool {
	var commandErr commandError
	text := err.Error()
	if errors.As(err, &commandErr) {
		text = commandErr.output
	}
	return strings.Contains(text, "No chain/target/match by that name")
}

func desiredSources(family dns.Family, addresses []dns.AllowedAddress) []string {
	seen := map[string]struct{}{}
	for _, address := range addresses {
		if address.Family != family {
			continue
		}
		source := normalizeSource(address.Value)
		if source != "" {
			seen[source] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func sourceDiff(current []string, desired []string) ([]string, []string) {
	currentSet := toSet(current)
	desiredSet := toSet(desired)

	added := make([]string, 0)
	for source := range desiredSet {
		if _, ok := currentSet[source]; !ok {
			added = append(added, source)
		}
	}

	removed := make([]string, 0)
	for source := range currentSet {
		if _, ok := desiredSet[source]; !ok {
			removed = append(removed, source)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func normalizeSource(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		if prefix.Bits() == prefix.Addr().BitLen() {
			return prefix.Addr().String()
		}
		return prefix.String()
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().String()
	}
	return value
}

func ruleJumpsTo(fields []string, target string) bool {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-j" && fields[i+1] == target {
			return true
		}
	}
	return false
}

func desiredJumpSpecs(chain string, interfaces []string) [][]string {
	specs := make([][]string, 0, len(interfaces))
	for _, iface := range interfaces {
		specs = append(specs, []string{"-i", iface, "-j", chain})
	}
	return specs
}

func dedupeStrings(values []string) []string {
	deduped := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		deduped = append(deduped, value)
	}
	return deduped
}

func parseChainRules(output string, chain string) [][]string {
	rules := make([][]string, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "-A" || fields[1] != chain {
			continue
		}
		rules = append(rules, append([]string(nil), fields[2:]...))
	}
	return rules
}

func firstRulesMatch(rules [][]string, desired [][]string) bool {
	if len(rules) < len(desired) {
		return false
	}
	for i, rule := range desired {
		if !ruleEquals(rules[i], rule) {
			return false
		}
	}
	return true
}

func isManagedJump(rule []string, chain string) bool {
	if len(rule) == 2 && rule[0] == "-j" && rule[1] == chain {
		return true
	}
	if len(rule) == 4 && rule[0] == "-i" && rule[2] == "-j" && rule[3] == chain {
		return true
	}
	return false
}

func containsRule(rules [][]string, want []string) bool {
	for _, rule := range rules {
		if ruleEquals(rule, want) {
			return true
		}
	}
	return false
}

func ruleEquals(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
