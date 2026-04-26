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

func TestLoadRejectsTrailingJSON(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW"
  }
}
{"unexpected": true}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "trailing content") {
		t.Fatalf("got error %v, want trailing-content rejection", err)
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

func TestLoadExtraAttachChains(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "interfaces": ["eth0"],
    "extra_attach_chains": ["DOCKER-USER", "CNI-FORWARD"]
  }
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Firewall.ExtraAttachChains) != 2 ||
		cfg.Firewall.ExtraAttachChains[0] != "DOCKER-USER" ||
		cfg.Firewall.ExtraAttachChains[1] != "CNI-FORWARD" {
		t.Fatalf("got %v", cfg.Firewall.ExtraAttachChains)
	}
}

func TestLoadRejectsInputAsExtraAttachChain(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "extra_attach_chains": ["INPUT"]
  }
}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "INPUT") {
		t.Fatalf("got error %v, want rejection of INPUT in extra_attach_chains", err)
	}
}

func TestLoadRejectsManagedChainAsExtraAttachChain(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "extra_attach_chains": ["DNS_FW"]
  }
}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "firewall.chain") {
		t.Fatalf("got error %v, want rejection of managed chain in extra_attach_chains", err)
	}
}

func TestLoadRejectsDuplicateExtraAttachChains(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "extra_attach_chains": ["DOCKER-USER", "DOCKER-USER"]
  }
}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("got error %v, want duplicate-entry rejection", err)
	}
}

func TestLoadRejectsInvalidExtraAttachChainName(t *testing.T) {
	path := writeConfig(t, `{
  "poll_interval": "1m",
  "records": ["_allow.example.com"],
  "firewall": {
    "chain": "DNS_FW",
    "extra_attach_chains": ["BAD CHAIN"]
  }
}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "extra_attach_chains") {
		t.Fatalf("got error %v, want extra_attach_chains validation error", err)
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
