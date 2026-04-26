package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{
  "poll_interval": "1m",
  "nameservers": ["1.1.1.1", "8.8.8.8:53"],
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "interfaces": ["eth0"]
  }
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval.Duration != time.Minute {
		t.Fatalf("got %s, want 1m", cfg.PollInterval.Duration)
	}
	if cfg.Firewall.Chain != "DNS_FW" {
		t.Fatalf("got chain %q", cfg.Firewall.Chain)
	}
	if len(cfg.Firewall.Interfaces) != 1 || cfg.Firewall.Interfaces[0] != "eth0" {
		t.Fatalf("got interfaces %v", cfg.Firewall.Interfaces)
	}
	if len(cfg.Records) != 1 || cfg.Records[0] != "_allow.example.com" {
		t.Fatalf("got records %v", cfg.Records)
	}
	if len(cfg.Nameservers) != 2 || cfg.Nameservers[0] != "1.1.1.1" || cfg.Nameservers[1] != "8.8.8.8:53" {
		t.Fatalf("got nameservers %v", cfg.Nameservers)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "interfaces": ["eth0"],
    "ipv4": true
  }
}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("got error %v, want unknown field error", err)
	}
}

func TestLoadRejectsInvalidChainName(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS FW",
    "interfaces": ["eth0"]
  }
}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "firewall.chain") {
		t.Fatalf("got error %v, want firewall.chain validation error", err)
	}
}

func TestLoadAllowsMissingInterfaces(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW"
  }
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Firewall.Interfaces) != 0 {
		t.Fatalf("got interfaces %v, want none", cfg.Firewall.Interfaces)
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
