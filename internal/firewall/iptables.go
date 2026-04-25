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
	config config.FirewallConfig
	dryRun bool
}

const (
	attachChain    = "INPUT"
	insertPosition = 1
)

func NewManager(cfg config.FirewallConfig, dryRun bool) *Manager {
	return &Manager{config: cfg, dryRun: dryRun}
}

func (m *Manager) Apply(ctx context.Context, addresses []dns.AllowedAddress) error {
	if err := m.applyFamily(ctx, "iptables", dns.IPv4, addresses); err != nil {
		return err
	}
	if err := m.applyFamily(ctx, "ip6tables", dns.IPv6, addresses); err != nil {
		return err
	}
	return nil
}

func (m *Manager) applyFamily(ctx context.Context, binary string, family dns.Family, addresses []dns.AllowedAddress) error {
	if err := m.ensureChain(ctx, binary); err != nil {
		return err
	}
	if err := m.ensureJump(ctx, binary); err != nil {
		return err
	}

	desired := desiredSources(family, addresses)
	if !m.dryRun {
		current, err := m.currentSources(ctx, binary)
		if err != nil {
			return err
		}
		added, removed := sourceDiff(current, desired)
		if len(added) == 0 && len(removed) == 0 {
			slog.Info("firewall already in sync", "binary", binary, "chain", m.config.Chain, "rules", len(desired))
			return nil
		}
		slog.Info(
			"firewall change detected",
			"binary", binary,
			"chain", m.config.Chain,
			"desired_rules", len(desired),
			"current_rules", len(current),
			"added", len(added),
			"removed", len(removed),
		)
		slog.Debug("firewall rule diff", "binary", binary, "added", added, "removed", removed)
	} else {
		slog.Info("dry-run firewall update planned", "binary", binary, "chain", m.config.Chain, "desired_rules", len(desired))
	}

	if err := m.restoreRules(ctx, binary, desired); err != nil {
		return err
	}
	slog.Info("firewall rules updated", "binary", binary, "chain", m.config.Chain, "rules", len(desired))
	return nil
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

func (m *Manager) ensureJump(ctx context.Context, binary string) error {
	_, err := m.command(ctx, binary, "-w", "-C", attachChain, "-j", m.config.Chain)
	if err == nil {
		return nil
	}
	if !isRuleMissing(err) {
		slog.Error("failed to check firewall managed chain jump", "binary", binary, "attach_chain", attachChain, "chain", m.config.Chain, "error", err)
		return err
	}
	slog.Info("firewall jump missing; inserting managed chain", "binary", binary, "attach_chain", attachChain, "chain", m.config.Chain, "position", insertPosition)
	return m.run(ctx, binary, "-w", "-I", attachChain, strconv.Itoa(insertPosition), "-j", m.config.Chain)
}

func (m *Manager) run(ctx context.Context, binary string, args ...string) error {
	if m.dryRun {
		slog.Info("dry-run firewall command", "command", append([]string{binary}, args...))
		return nil
	}

	output, err := m.command(ctx, binary, args...)
	if err != nil {
		slog.Error("firewall command failed", "binary", binary, "args", args, "output", strings.TrimSpace(output), "error", err)
		return err
	}
	return nil
}

func (m *Manager) currentSources(ctx context.Context, binary string) ([]string, error) {
	output, err := m.output(ctx, binary, "-w", "-S", m.config.Chain)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "-s" {
				continue
			}
			if !ruleAccepts(fields) {
				continue
			}
			source := normalizeSource(fields[i+1])
			if source != "" {
				seen[source] = struct{}{}
			}
		}
	}
	return sortedKeys(seen), nil
}

func (m *Manager) output(ctx context.Context, binary string, args ...string) (string, error) {
	output, err := m.command(ctx, binary, args...)
	if err != nil {
		slog.Error("firewall command failed", "binary", binary, "args", args, "output", strings.TrimSpace(output), "error", err)
		return "", err
	}
	return output, nil
}

func (m *Manager) restoreRules(ctx context.Context, binary string, sources []string) error {
	payload := restoreInput(m.config.Chain, sources)
	restoreBinary := restoreBinaryFor(binary)
	if m.dryRun {
		slog.Info("dry-run firewall restore command", "command", []string{restoreBinary, "--noflush"}, "input", payload)
		return nil
	}

	cmd := exec.CommandContext(ctx, restoreBinary, "--noflush")
	cmd.Stdin = strings.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		commandErr := commandError{
			binary: restoreBinary,
			args:   []string{"--noflush"},
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

func restoreInput(chain string, sources []string) string {
	var builder strings.Builder
	builder.WriteString("*filter\n")
	builder.WriteString("-F ")
	builder.WriteString(chain)
	builder.WriteByte('\n')
	for _, source := range sources {
		builder.WriteString("-A ")
		builder.WriteString(chain)
		builder.WriteString(" -s ")
		builder.WriteString(source)
		builder.WriteString(" -j ACCEPT\n")
	}
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

func ruleAccepts(fields []string) bool {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-j" && fields[i+1] == "ACCEPT" {
			return true
		}
	}
	return false
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
