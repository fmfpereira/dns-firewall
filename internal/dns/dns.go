package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Family string

const (
	IPv4 Family = "ipv4"
	IPv6 Family = "ipv6"
)

type AllowedAddress struct {
	Family Family
	Source string
	Value  string
}

var valueSplitter = regexp.MustCompile(`[,\s;]+`)

type ResolverGroup struct {
	resolvers []namedResolver
}

type namedResolver struct {
	name     string
	resolver *net.Resolver
}

func NewResolverGroup(nameservers []string) *ResolverGroup {
	if len(nameservers) == 0 {
		return &ResolverGroup{
			resolvers: []namedResolver{{name: "os-default", resolver: net.DefaultResolver}},
		}
	}

	resolvers := make([]namedResolver, 0, len(nameservers))
	for _, nameserver := range nameservers {
		resolvers = append(resolvers, namedResolver{
			name:     nameserver,
			resolver: resolverFor(nameserver),
		})
	}
	return &ResolverGroup{resolvers: resolvers}
}

func CollectAllowedAddresses(ctx context.Context, records []string, nameservers []string) ([]AllowedAddress, error) {
	resolvers := NewResolverGroup(nameservers)
	seen := map[string]AllowedAddress{}
	for _, record := range records {
		txtValues, err := resolvers.LookupTXT(ctx, record)
		if err != nil {
			return nil, fmt.Errorf("lookup TXT %s: %w", record, err)
		}

		slog.Info("TXT record resolved", "record", record, "values", len(txtValues))
		for _, txtValue := range txtValues {
			for _, value := range SplitTXTValue(txtValue) {
				for _, address := range ResolveTXTValue(ctx, resolvers, value, record) {
					seen[string(address.Family)+"|"+address.Value] = address
				}
			}
		}
	}

	allowlist := make([]AllowedAddress, 0, len(seen))
	for _, address := range seen {
		allowlist = append(allowlist, address)
	}
	sort.Slice(allowlist, func(i, j int) bool {
		if allowlist[i].Family != allowlist[j].Family {
			return allowlist[i].Family < allowlist[j].Family
		}
		return allowlist[i].Value < allowlist[j].Value
	})
	return allowlist, nil
}

func (g *ResolverGroup) LookupTXT(ctx context.Context, name string) ([]string, error) {
	var lookupErrs []string
	for _, resolver := range g.resolvers {
		values, err := resolver.resolver.LookupTXT(ctx, name)
		if err == nil {
			slog.Info("DNS TXT lookup succeeded", "record", name, "nameserver", resolver.name, "values", len(values))
			return values, nil
		}
		logDNSError("DNS TXT lookup failed", resolver.name, name, err)
		lookupErrs = append(lookupErrs, fmt.Sprintf("%s: %v", resolver.name, err))
	}
	return nil, fmt.Errorf("all nameservers failed: %s", strings.Join(lookupErrs, "; "))
}

func (g *ResolverGroup) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	var lookupErrs []string
	for _, resolver := range g.resolvers {
		values, err := resolver.resolver.LookupIPAddr(ctx, name)
		if err == nil {
			slog.Info("DNS host lookup succeeded", "host", name, "nameserver", resolver.name, "addresses", len(values))
			return values, nil
		}
		logDNSError("DNS host lookup failed", resolver.name, name, err)
		lookupErrs = append(lookupErrs, fmt.Sprintf("%s: %v", resolver.name, err))
	}
	return nil, fmt.Errorf("all nameservers failed: %s", strings.Join(lookupErrs, "; "))
}

func SplitTXTValue(value string) []string {
	parts := valueSplitter.Split(strings.TrimSpace(value), -1)
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func ResolveTXTValue(ctx context.Context, resolvers *ResolverGroup, value string, sourceRecord string) []AllowedAddress {
	if address, ok := parseAddress(value); ok {
		return []AllowedAddress{address}
	}

	hostname := strings.TrimSuffix(value, ".")
	if !isHostname(hostname) {
		slog.Warn("ignoring invalid TXT value", "record", sourceRecord, "value", value)
		return nil
	}

	ipAddrs, err := resolvers.LookupIPAddr(ctx, hostname)
	if err != nil {
		slog.Warn("could not resolve hostname from TXT value", "record", sourceRecord, "hostname", hostname, "error", err)
		return nil
	}

	seen := map[string]AllowedAddress{}
	for _, ipAddr := range ipAddrs {
		addr, ok := netip.AddrFromSlice(ipAddr.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()

		family := IPv6
		if addr.Is4() {
			family = IPv4
		}
		seen[string(family)+"|"+addr.String()] = AllowedAddress{
			Family: family,
			Source: value,
			Value:  addr.String(),
		}
	}

	addresses := make([]AllowedAddress, 0, len(seen))
	for _, address := range seen {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].Family != addresses[j].Family {
			return addresses[i].Family < addresses[j].Family
		}
		return addresses[i].Value < addresses[j].Value
	})
	return addresses
}

func parseAddress(value string) (AllowedAddress, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		family := IPv6
		if prefix.Addr().Is4() {
			family = IPv4
		}
		return AllowedAddress{Family: family, Source: value, Value: prefix.String()}, true
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return AllowedAddress{}, false
	}
	addr = addr.Unmap()
	family := IPv6
	if addr.Is4() {
		family = IPv4
	}
	return AllowedAddress{Family: family, Source: value, Value: addr.String()}, true
}

func isHostname(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func resolverFor(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}

	address := nameserverAddress(server)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func nameserverAddress(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}

	unbracketed := strings.TrimPrefix(strings.TrimSuffix(server, "]"), "[")
	if addr, err := netip.ParseAddr(unbracketed); err == nil {
		return net.JoinHostPort(addr.String(), "53")
	}

	return net.JoinHostPort(server, "53")
}

func logDNSError(message string, nameserver string, name string, err error) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		reason := "dns_error"
		switch {
		case dnsErr.IsNotFound:
			reason = "record_not_found"
		case dnsErr.IsTimeout || dnsErr.IsTemporary:
			reason = "nameserver_unavailable"
		}
		slog.Warn(message, "nameserver", nameserver, "name", name, "reason", reason, "error", err)
		return
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		slog.Warn(message, "nameserver", nameserver, "name", name, "reason", "lookup_interrupted", "error", err)
		return
	}

	slog.Warn(message, "nameserver", nameserver, "name", name, "reason", "resolver_failure", "error", err)
}
