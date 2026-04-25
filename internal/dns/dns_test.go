package dns

import (
	"context"
	"testing"
)

func TestSplitTXTValue(t *testing.T) {
	got := SplitTXTValue("192.0.2.10;admin.example.com;2001:db8::1")
	want := []string{"192.0.2.10", "admin.example.com", "2001:db8::1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestResolveDirectIP(t *testing.T) {
	addresses := ResolveTXTValue(context.Background(), NewResolverGroup(nil), "192.0.2.10", "_allow.example.com")
	if len(addresses) != 1 {
		t.Fatalf("got %v addresses, want 1", len(addresses))
	}
	if addresses[0].Family != IPv4 || addresses[0].Value != "192.0.2.10" {
		t.Fatalf("got %+v", addresses[0])
	}
}

func TestResolveCIDR(t *testing.T) {
	addresses := ResolveTXTValue(context.Background(), NewResolverGroup(nil), "192.0.2.9/24", "_allow.example.com")
	if len(addresses) != 1 {
		t.Fatalf("got %v addresses, want 1", len(addresses))
	}
	if addresses[0].Family != IPv4 || addresses[0].Value != "192.0.2.0/24" {
		t.Fatalf("got %+v", addresses[0])
	}
}

func TestRejectInvalidValue(t *testing.T) {
	addresses := ResolveTXTValue(context.Background(), NewResolverGroup(nil), "not_a_host!", "_allow.example.com")
	if len(addresses) != 0 {
		t.Fatalf("got %v, want no addresses", addresses)
	}
}

func TestMultipleTXTRecordsCanBeSplit(t *testing.T) {
	txtRecords := []string{
		"192.0.2.10;admin.example.com",
		"2001:db8::1;198.51.100.0/24",
	}
	var got []string
	for _, txtRecord := range txtRecords {
		got = append(got, SplitTXTValue(txtRecord)...)
	}
	want := []string{"192.0.2.10", "admin.example.com", "2001:db8::1", "198.51.100.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNameserverAddress(t *testing.T) {
	tests := map[string]string{
		"1.1.1.1":                   "1.1.1.1:53",
		"1.1.1.1:5353":              "1.1.1.1:5353",
		"2001:4860:4860::8888":      "[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8888]":    "[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8888]:53": "[2001:4860:4860::8888]:53",
		"dns.example.com":           "dns.example.com:53",
		"dns.example.com:5353":      "dns.example.com:5353",
	}

	for input, want := range tests {
		if got := nameserverAddress(input); got != want {
			t.Fatalf("nameserverAddress(%q) = %q, want %q", input, got, want)
		}
	}
}
