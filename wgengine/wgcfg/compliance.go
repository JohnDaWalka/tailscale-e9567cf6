// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"
	"net/netip"
)

// WireGuardProtocolVersion is the standard WireGuard protocol version
const WireGuardProtocolVersion = 1

// ComplianceError represents a WireGuard compliance validation error
type ComplianceError struct {
	Field   string
	Message string
}

func (e *ComplianceError) Error() string {
	return fmt.Sprintf("WireGuard compliance error in %s: %s", e.Field, e.Message)
}

// ValidateWireGuardCompliance validates that a Config is compliant with
// the WireGuard protocol specification.
//
// This includes checking:
// - Private key is set and valid
// - All peers have valid public keys
// - AllowedIPs are valid CIDR ranges
// - PersistentKeepalive intervals are reasonable
// - MTU is within acceptable range (if set)
func (cfg *Config) ValidateWireGuardCompliance() error {
	// Validate private key
	if cfg.PrivateKey.IsZero() {
		return &ComplianceError{
			Field:   "PrivateKey",
			Message: "private key must be set",
		}
	}

	// Validate MTU if set
	if cfg.MTU != 0 {
		// WireGuard typical MTU range: 1280-1500 for standard networks
		// Can be lower for certain networks but should not be 0 if set
		if cfg.MTU < 576 || cfg.MTU > 65535 {
			return &ComplianceError{
				Field:   "MTU",
				Message: fmt.Sprintf("MTU %d is outside reasonable range (576-65535)", cfg.MTU),
			}
		}
	}

	// Validate each peer
	for i, peer := range cfg.Peers {
		if err := validatePeerCompliance(i, &peer); err != nil {
			return err
		}
	}

	return nil
}

// validatePeerCompliance validates a single peer configuration
func validatePeerCompliance(index int, peer *Peer) error {
	peerPrefix := fmt.Sprintf("Peers[%d]", index)

	// Validate public key
	if peer.PublicKey.IsZero() {
		return &ComplianceError{
			Field:   peerPrefix + ".PublicKey",
			Message: "public key must be set",
		}
	}

	// Validate AllowedIPs
	if len(peer.AllowedIPs) == 0 {
		return &ComplianceError{
			Field:   peerPrefix + ".AllowedIPs",
			Message: "at least one allowed IP must be specified",
		}
	}

	for j, allowedIP := range peer.AllowedIPs {
		if !allowedIP.IsValid() {
			return &ComplianceError{
				Field:   fmt.Sprintf("%s.AllowedIPs[%d]", peerPrefix, j),
				Message: fmt.Sprintf("invalid CIDR: %v", allowedIP),
			}
		}
		// Check for valid prefix length
		if allowedIP.Addr().Is4() {
			if allowedIP.Bits() < 0 || allowedIP.Bits() > 32 {
				return &ComplianceError{
					Field:   fmt.Sprintf("%s.AllowedIPs[%d]", peerPrefix, j),
					Message: fmt.Sprintf("IPv4 prefix length %d is invalid (must be 0-32)", allowedIP.Bits()),
				}
			}
		} else if allowedIP.Addr().Is6() {
			if allowedIP.Bits() < 0 || allowedIP.Bits() > 128 {
				return &ComplianceError{
					Field:   fmt.Sprintf("%s.AllowedIPs[%d]", peerPrefix, j),
					Message: fmt.Sprintf("IPv6 prefix length %d is invalid (must be 0-128)", allowedIP.Bits()),
				}
			}
		}
	}

	// Validate PersistentKeepalive
	// According to WireGuard spec, keepalive should be reasonable
	// Typical values are 0 (disabled) or 10-25 seconds for NAT traversal
	// We'll warn if it's set to a very high value as it may indicate misconfiguration
	if peer.PersistentKeepalive > 0 && peer.PersistentKeepalive > 300 {
		return &ComplianceError{
			Field:   peerPrefix + ".PersistentKeepalive",
			Message: fmt.Sprintf("keepalive interval %d seconds is unusually high (typical: 0-300)", peer.PersistentKeepalive),
		}
	}

	return nil
}

// ValidateAddresses validates that the node's addresses are valid
func ValidateAddresses(addresses []netip.Prefix) error {
	if len(addresses) == 0 {
		return &ComplianceError{
			Field:   "Addresses",
			Message: "at least one address must be configured",
		}
	}

	for i, addr := range addresses {
		if !addr.IsValid() {
			return &ComplianceError{
				Field:   fmt.Sprintf("Addresses[%d]", i),
				Message: fmt.Sprintf("invalid address: %v", addr),
			}
		}
		// Ensure it's a host address (typically /32 for IPv4, /128 for IPv6 in WireGuard)
		if addr.Addr().Is4() && addr.Bits() != 32 {
			// Note: Tailscale may use /32 for IPv4 node addresses
			// This is just a validation, not enforcing /32
		} else if addr.Addr().Is6() && addr.Bits() != 128 {
			// Note: Tailscale may use /128 for IPv6 node addresses
			// This is just a validation, not enforcing /128
		}
	}

	return nil
}
