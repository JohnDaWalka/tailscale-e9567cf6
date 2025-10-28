// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg_test

import (
	"fmt"
	"net/netip"

	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgcfg"
)

// Example_wireGuardCompliance demonstrates WireGuard compliance validation
func Example_wireGuardCompliance() {
	// Create a valid configuration
	privateKey := key.NewNode()
	peerKey := key.NewNode().Public()

	validConfig := &wgcfg.Config{
		Name:       "node1.example.ts.net.",
		PrivateKey: privateKey,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/32"),
		},
		MTU: 1280,
		Peers: []wgcfg.Peer{
			{
				PublicKey: peerKey,
				AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.0/10"),
				},
				PersistentKeepalive: 25,
			},
		},
	}

	// Validate the configuration
	if err := validConfig.ValidateWireGuardCompliance(); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
	} else {
		fmt.Println("Configuration is WireGuard compliant")
	}

	// Output: Configuration is WireGuard compliant
}

// Example_invalidConfiguration demonstrates validation failure
func Example_invalidConfiguration() {
	// Create an invalid configuration (missing private key)
	invalidConfig := &wgcfg.Config{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/32"),
		},
	}

	// Validate the configuration
	if err := invalidConfig.ValidateWireGuardCompliance(); err != nil {
		fmt.Println("Validation failed: private key must be set")
	}

	// Output: Validation failed: private key must be set
}

// Example_validateAddresses demonstrates address validation
func Example_validateAddresses() {
	addresses := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/32"),
		netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
	}

	if err := wgcfg.ValidateAddresses(addresses); err != nil {
		fmt.Printf("Address validation failed: %v\n", err)
	} else {
		fmt.Println("Dual-stack addresses are valid")
	}

	// Output: Dual-stack addresses are valid
}
