# DNS Firewall

`dns-firewall` is a Go service that turns DNS TXT records into an iptables allowlist for inbound traffic.

It resolves one or more TXT records, expands any hostnames found there to their current A and AAAA addresses, and keeps a managed firewall chain in sync. Traffic from an allowlisted source returns to the normal firewall path, so the rest of your host, Docker, or Podman rules still decide whether the connection is ultimately accepted. Traffic from a non-allowlisted source is dropped at the managed gate.

Outbound traffic is not blocked. Established and related connections return before source checks, so replies for connections initiated by the host continue to work.

Runtime requirements:

- `iptables` for IPv4 rules
- `ip6tables` for IPv6 rules
- `iptables-restore` and `ip6tables-restore` for transactional rule updates
- `ip` from `iproute2` for default-route interface detection
- `systemd` for running as a Linux service

## How It Works

On each sync, the service:

1. Reads the configured DNS TXT records.
2. Splits each TXT value into IP addresses, CIDR ranges, or hostnames.
3. Resolves hostnames to A and AAAA records.
4. Builds separate IPv4 and IPv6 source allowlists.
5. Rewrites only the managed iptables/ip6tables chain.
6. Ensures configured attach chains jump to the managed chain first.

The managed chain has this shape:

```text
DNS_FIREWALL_ALLOW -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
DNS_FIREWALL_ALLOW -m conntrack --ctstate INVALID -j DROP
DNS_FIREWALL_ALLOW -s <resolved-ip-or-cidr> -j RETURN
DNS_FIREWALL_ALLOW -j DROP
```

The source `RETURN` rules do not accept traffic by themselves. They return to the parent chain so any later firewall rules still apply.

## TXT Record Format

Each TXT value can contain an IP address, CIDR range, or hostname. A DNS name may publish multiple TXT records, and each TXT record may contain multiple values separated by semicolons, commas, or whitespace.

Examples:

```text
_allowlist.example.com TXT "203.0.113.10;admin.example.com;2001:db8::10"
_allowlist.example.com TXT "198.51.100.0/24"
```

Hostnames are resolved to their current A and AAAA records before firewall rules are written.

Invalid TXT values are ignored with a warning. DNS lookup failures for configured TXT records or hostnames abort that sync and keep the existing firewall rules.

## Configuration

Copy the example config:

```bash
sudo mkdir -p /etc/dns-firewall
sudo cp config/dns-firewall.json.example /etc/dns-firewall/config.json
```

Edit `/etc/dns-firewall/config.json`:

```json
{
  "poll_interval": "5m",
  "dry_run": false,
  "nameservers": [
    "1.1.1.1",
    "8.8.8.8"
  ],
  "records": [
    "_allowlist.example.com",
    "_admins.example.net"
  ],
  "firewall": {
    "chain": "DNS_FIREWALL_ALLOW"
  }
}
```

`nameservers` is optional. If it is omitted or empty, the service uses the default resolver configured on the operating system. Values can be plain IPs, such as `1.1.1.1`, IPv6 literals, such as `2001:4860:4860::8888`, bracketed IPv6 literals, such as `[2001:4860:4860::8888]`, or `host:port`, such as `1.1.1.1:53`.

The configurable firewall setting is the managed chain name. By default, the service scopes the gate to the interface from the system default route for each IP family, equivalent to the interface used for `0.0.0.0/0` and `::/0`.

For complex hosts, `firewall.interfaces` can be set explicitly:

```json
"firewall": {
  "chain": "DNS_FIREWALL_ALLOW",
  "interfaces": ["eth0", "ppp0"]
}
```

Use explicit interfaces for multi-WAN, VPN default routes, policy routing, or failover setups. Do not list LAN, loopback, Docker, or other internal interfaces unless you also want those interfaces gated by the DNS allowlist. See `config/dns-firewall.multi-wan.json.example` for a full sample.

The service attaches the managed chain to `INPUT` at position `1` for each detected or configured interface, manages both IPv4 and IPv6, and keeps existing rules if DNS lookup fails, if a hostname published in TXT cannot be resolved, or if the records resolve to no addresses.

`INPUT` only sees packets destined for the host itself. Container traffic is DNATed in `PREROUTING` and routed through `FORWARD`, so a managed `INPUT` jump does not gate published container ports. Set `firewall.extra_attach_chains` to also attach the managed chain to runtime-specific hook chains:

```json
"firewall": {
  "chain": "DNS_FIREWALL_ALLOW",
  "extra_attach_chains": ["DOCKER-USER"]
}
```

Docker preserves `DOCKER-USER` across daemon restarts and leaves it for user policy, making it the normal place to gate Docker-published ports. See `config/dns-firewall.docker.json.example` for a full sample. For Podman use `CNI-FORWARD` (CNI backend) or `NETAVARK-FORWARD` (Netavark backend).

The same RETURN/INVALID-DROP/source-RETURN/DROP layout is applied to extra chains. A source match returns to the runtime chain, so allowed sources continue through Docker or Podman's normal forwarding logic. Each configured extra chain must already exist; if it does not, the sync fails before inserting new jumps. Removing a chain from the config does not remove a previously inserted jump; clean it up manually with:

```bash
sudo iptables -D <chain> -i <iface> -j <managed-chain>
sudo ip6tables -D <chain> -i <iface> -j <managed-chain>
```

If no default route exists for an IP family, the service removes its managed `INPUT` jumps for that family so stale public-interface gates are not left behind.

The gate is enforced per family for new inbound connections. If your TXT records resolve to IPv4 addresses only, new inbound IPv6 connections on the gated interface are dropped, and vice versa. Reply traffic for outbound connections still flows via the conntrack rule. On dual-stack hosts, publish both families in DNS unless you intentionally want to block new inbound traffic for one family.

## Install From A Release

Download the release tarball for your machine from the GitHub Releases page.

Release assets use these names:

```text
dns-firewall_<version>_linux_amd64.tar.gz
dns-firewall_<version>_linux_arm64.tar.gz
dns-firewall_<version>_linux_armv7.tar.gz
checksums.txt
```

Example for `linux_amd64`:

```bash
OWNER=your-github-owner
# Pick the latest release tag, or replace with a specific tag (e.g. VERSION=v0.3.0) to pin.
VERSION=$(curl -fsSL "https://api.github.com/repos/${OWNER}/dns-firewall/releases/latest" \
  | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO "https://github.com/${OWNER}/dns-firewall/releases/download/${VERSION}/dns-firewall_${VERSION}_linux_amd64.tar.gz"
curl -LO "https://github.com/${OWNER}/dns-firewall/releases/download/${VERSION}/checksums.txt"
sha256sum -c checksums.txt --ignore-missing
tar -xzf "dns-firewall_${VERSION}_linux_amd64.tar.gz"
```

Install the release files:

```bash
sudo install -m 0755 dns-firewall /usr/local/bin/dns-firewall
sudo mkdir -p /etc/dns-firewall
sudo install -m 0644 dns-firewall.json.example /etc/dns-firewall/config.json
sudo install -m 0644 dns-firewall.service /etc/systemd/system/dns-firewall.service
```

Edit `/etc/dns-firewall/config.json` before starting the service.

## Build From Source

Build and install locally:

```bash
go build -o dns-firewall ./cmd/dns-firewall
sudo install -m 0755 dns-firewall /usr/local/bin/dns-firewall
```

Install the example config and systemd unit from the source tree:

```bash
sudo mkdir -p /etc/dns-firewall
sudo cp config/dns-firewall.json.example /etc/dns-firewall/config.json
sudo cp systemd/dns-firewall.service /etc/systemd/system/dns-firewall.service
```

Edit `/etc/dns-firewall/config.json` before starting the service.

## Run The Service

Run a dry-run without changing firewall rules:

```bash
sudo dns-firewall --config /etc/dns-firewall/config.json --once --dry-run
```

Dry-run still reads firewall state for configured attach chains. If `firewall.extra_attach_chains` includes Docker or Podman chains that do not exist yet, dry-run fails the same way a real sync would; start the container runtime first or remove the extra chain from the dry-run config.

Apply rules once:

```bash
sudo dns-firewall --config /etc/dns-firewall/config.json --once
```

Start the systemd service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dns-firewall.service
```

Check logs:

```bash
sudo journalctl -u dns-firewall.service -f
```

The service creates a dedicated chain and inserts a jump to it from `INPUT`:

```text
INPUT -i <internet-interface> -> DNS_FIREWALL_ALLOW
DNS_FIREWALL_ALLOW -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
DNS_FIREWALL_ALLOW -m conntrack --ctstate INVALID -j DROP
DNS_FIREWALL_ALLOW -s <resolved-ip> -j RETURN
DNS_FIREWALL_ALLOW -j DROP
```

The DNS allowlist is a first gate, not the final allow decision. The leading conntrack rule lets reply traffic for outbound connections through, so the gate only filters new inbound connections. The explicit `INVALID` drop accounts for malformed or out-of-window packets in `iptables -L -v` counters instead of folding them into the catch-all. A matching new connection from an allowlisted source returns to `INPUT` so later firewall rules are still evaluated. New inbound connections from non-matching sources on a configured internet-facing interface are dropped before later rules run.

It updates only `DNS_FIREWALL_ALLOW`, using `iptables-restore --noflush` / `ip6tables-restore --noflush` so the managed chain rewrite is applied as one transaction. The service also keeps its `INPUT` jump rules first and removes stale jumps to the managed chain when the detected or configured interface list changes.

## Known Behavior

- The allowlist applies to new inbound connections. Established and related flows return before source checks, so existing sessions can continue after a DNS allowlist change.
- Configured `firewall.extra_attach_chains` must already exist for both real syncs and dry-runs. For Docker, start Docker before applying a config that uses `DOCKER-USER`; for Podman, use the chain created by the active networking backend.
- IPv4 and IPv6 are managed independently. If TXT records publish only one family, new inbound connections for the other family are dropped on gated interfaces while outbound reply traffic for that family can still pass through conntrack.
- Invalid TXT tokens are ignored with a warning. Failed DNS lookups for configured records or hostnames keep the previous firewall state.

## Logging

The service writes structured, levelled logs to stdout/stderr. Under systemd these are captured by journald with `SyslogIdentifier=dns-firewall`; no custom log file is created.

Useful commands:

```bash
sudo journalctl -u dns-firewall.service -f
sudo journalctl -t dns-firewall --since "1 hour ago"
```

The daemon logs DNS lookup failures by nameserver and reason, including record-not-found and nameserver-unavailable cases. Firewall updates are logged only when the managed chain changes; unchanged syncs log as already in sync.

## Development Tests

```bash
go test ./...
```

## License

MIT License. See [LICENSE](LICENSE).
