package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
)

type Duration struct {
	time.Duration
}

type Config struct {
	PollInterval Duration       `json:"poll_interval"`
	DryRun       bool           `json:"dry_run"`
	Nameservers  []string       `json:"nameservers,omitempty"`
	Records      []string       `json:"records"`
	Firewall     FirewallConfig `json:"firewall"`
}

type FirewallConfig struct {
	Chain             string   `json:"chain"`
	Interfaces        []string `json:"interfaces"`
	ExtraAttachChains []string `json:"extra_attach_chains,omitempty"`
}

var chainNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)
var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		PollInterval: Duration{Duration: 5 * time.Minute},
		Firewall: FirewallConfig{
			Chain: "DNS_FIREWALL_ALLOW",
		},
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return Config{}, fmt.Errorf("unexpected trailing content after configuration object: %w", err)
		}
		return Config{}, fmt.Errorf("unexpected trailing content after configuration object")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.PollInterval.Duration < 15*time.Second {
		return fmt.Errorf("poll_interval must be at least 15s")
	}
	if len(c.Records) == 0 {
		return fmt.Errorf("at least one DNS TXT record is required")
	}
	for i, record := range c.Records {
		if record == "" {
			return fmt.Errorf("records[%d] must not be empty", i)
		}
	}
	for i, nameserver := range c.Nameservers {
		if nameserver == "" {
			return fmt.Errorf("nameservers[%d] must not be empty", i)
		}
	}
	if c.Firewall.Chain == "" {
		return fmt.Errorf("firewall.chain is required")
	}
	if !chainNamePattern.MatchString(c.Firewall.Chain) {
		return fmt.Errorf("firewall.chain must be 1-28 characters using only letters, digits, underscore, or hyphen")
	}
	for i, iface := range c.Firewall.Interfaces {
		if iface == "" {
			return fmt.Errorf("firewall.interfaces[%d] must not be empty", i)
		}
		if !interfaceNamePattern.MatchString(iface) {
			return fmt.Errorf("firewall.interfaces[%d] must be 1-15 characters using only letters, digits, underscore, dot, colon, or hyphen", i)
		}
	}
	seenChains := map[string]struct{}{}
	for i, chain := range c.Firewall.ExtraAttachChains {
		if chain == "" {
			return fmt.Errorf("firewall.extra_attach_chains[%d] must not be empty", i)
		}
		if !chainNamePattern.MatchString(chain) {
			return fmt.Errorf("firewall.extra_attach_chains[%d] must be 1-28 characters using only letters, digits, underscore, or hyphen", i)
		}
		if chain == "INPUT" {
			return fmt.Errorf("firewall.extra_attach_chains[%d] must not be INPUT (already managed)", i)
		}
		if chain == c.Firewall.Chain {
			return fmt.Errorf("firewall.extra_attach_chains[%d] must not equal firewall.chain", i)
		}
		if _, dup := seenChains[chain]; dup {
			return fmt.Errorf("firewall.extra_attach_chains[%d] is a duplicate of an earlier entry: %q", i, chain)
		}
		seenChains[chain] = struct{}{}
	}
	return nil
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string such as %q: %w", "5m", err)
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = duration
	return nil
}
