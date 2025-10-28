// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"net/netip"
	"testing"

	"tailscale.com/types/key"
)

func TestValidateWireGuardCompliance(t *testing.T) {
	validPrivKey := key.NewNode()
	validPubKey := validPrivKey.Public()
	
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				MTU: 1280,
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
						PersistentKeepalive: 25,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing private key",
			config: &Config{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "private key must be set",
		},
		{
			name: "invalid MTU - too small",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				MTU: 500,
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "MTU 500 is outside reasonable range (576-65535)",
		},
		{
			name: "valid MTU - high end",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				MTU: 9000,
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "peer with missing public key",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				Peers: []Peer{
					{
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "public key must be set",
		},
		{
			name: "peer with no allowed IPs",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				Peers: []Peer{
					{
						PublicKey:  validPubKey,
						AllowedIPs: []netip.Prefix{},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one allowed IP must be specified",
		},
		{
			name: "peer with excessive keepalive",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
						PersistentKeepalive: 500,
					},
				},
			},
			wantErr: true,
			errMsg:  "keepalive interval 500 seconds is unusually high (typical: 0-300)",
		},
		{
			name: "valid IPv6 config",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				},
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
						},
						PersistentKeepalive: 0,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple peers valid",
			config: &Config{
				PrivateKey: validPrivKey,
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				},
				Peers: []Peer{
					{
						PublicKey: validPubKey,
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.0/10"),
						},
						PersistentKeepalive: 25,
					},
					{
						PublicKey: key.NewNode().Public(),
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("100.64.64.0/24"),
						},
						PersistentKeepalive: 0,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateWireGuardCompliance()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWireGuardCompliance() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if compErr, ok := err.(*ComplianceError); ok {
					if compErr.Message != tt.errMsg {
						t.Errorf("ValidateWireGuardCompliance() error message = %q, want %q", compErr.Message, tt.errMsg)
					}
				}
			}
		})
	}
}

func TestValidateAddresses(t *testing.T) {
	tests := []struct {
		name      string
		addresses []netip.Prefix
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid IPv4 address",
			addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			wantErr: false,
		},
		{
			name: "valid IPv6 address",
			addresses: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			wantErr: false,
		},
		{
			name: "valid dual stack",
			addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			wantErr: false,
		},
		{
			name:      "no addresses",
			addresses: []netip.Prefix{},
			wantErr:   true,
			errMsg:    "at least one address must be configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddresses(tt.addresses)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAddresses() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if compErr, ok := err.(*ComplianceError); ok {
					if compErr.Message != tt.errMsg {
						t.Errorf("ValidateAddresses() error message = %q, want %q", compErr.Message, tt.errMsg)
					}
				}
			}
		})
	}
}

func TestComplianceErrorFormat(t *testing.T) {
	err := &ComplianceError{
		Field:   "TestField",
		Message: "test message",
	}
	
	expected := "WireGuard compliance error in TestField: test message"
	if err.Error() != expected {
		t.Errorf("ComplianceError.Error() = %q, want %q", err.Error(), expected)
	}
}
