# DNS Firewall

`dns-firewall` is a Go service that reads one or more DNS TXT records, resolves the IP addresses or hostnames published there, and keeps an iptables allowlist chain in sync.

Runtime requirements:

- `iptables` for IPv4 rules
- `ip6tables` for IPv6 rules
- `iptables-restore` and `ip6tables-restore` for transactional rule updates
- `systemd` for running as a Linux service

## TXT Record Format

Each TXT value can contain an IP address, CIDR range, or hostname. A DNS name may publish multiple TXT records, and each TXT record may contain multiple values separated with semicolons.

Examples:

```text
_allowlist.example.com TXT "203.0.113.10;admin.example.com;2001:db8::10"
_allowlist.example.com TXT "198.51.100.0/24"
```

Hostnames are resolved to their current A and AAAA records before firewall rules are written.

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

`nameservers` is optional. If it is omitted or empty, the service uses the default resolver configured on the operating system. Values can be plain IPs, such as `1.1.1.1`, IPv6 literals, such as `2001:4860:4860::8888`, or `host:port`, such as `1.1.1.1:53`.

The only configurable firewall setting is the managed chain name. The service always attaches that chain to `INPUT` at position `1`, manages both IPv4 and IPv6, and keeps existing allowlist rules if DNS lookup fails or resolves to no addresses.

## Test A Sync

Run a dry-run without touching iptables:

```bash
go run ./cmd/dns-firewall --config config/dns-firewall.json.example --once --dry-run
```

Apply rules for real:

```bash
sudo dns-firewall --config /etc/dns-firewall/config.json --once
```

The service creates a dedicated chain and inserts a jump to it from `INPUT`:

```text
INPUT -> DNS_FIREWALL_ALLOW
DNS_FIREWALL_ALLOW -s <resolved-ip> -j ACCEPT
```

It updates only `DNS_FIREWALL_ALLOW`, using `iptables-restore --noflush` / `ip6tables-restore --noflush` so the managed chain rewrite is applied as one transaction.

## Install As A Linux Service

Build and install the binary:

```bash
go build -o dns-firewall ./cmd/dns-firewall
sudo install -m 0755 dns-firewall /usr/local/bin/dns-firewall
```

Install and start the systemd unit:

```bash
sudo cp systemd/dns-firewall.service /etc/systemd/system/dns-firewall.service
sudo systemctl daemon-reload
sudo systemctl enable --now dns-firewall.service
```

Check logs:

```bash
sudo journalctl -u dns-firewall.service -f
```

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
