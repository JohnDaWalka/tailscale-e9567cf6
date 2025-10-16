# WireGuard Protocol Compliance

This document describes Tailscale's compliance with the WireGuard protocol specification.

## Overview

Tailscale is built on top of WireGuard®, a modern, high-performance VPN protocol. This implementation ensures full compliance with the WireGuard protocol specification while adding Tailscale-specific features for mesh networking, key management, and NAT traversal.

## WireGuard Protocol Version

Tailscale uses **WireGuard Protocol Version 1**, which is the standard and only version of the WireGuard protocol. This is enforced in the codebase:

- Protocol version is always set to `1` in UAPI configuration
- Configuration parser validates that protocol_version is `1`
- Any other protocol version is rejected with an error

## Compliance Validation

The `wgengine/wgcfg` package includes comprehensive compliance validation to ensure all WireGuard configurations meet protocol standards.

### Configuration Requirements

#### Device Configuration

1. **Private Key**
   - Must be set and non-zero
   - Automatically clamped by WireGuard (userspace or kernel)
   - Generated using Curve25519 cryptography

2. **MTU (Maximum Transmission Unit)**
   - If specified, must be within the range 576-65535 bytes
   - Typical values: 1280-1500 for standard networks
   - Can be lower for certain network conditions
   - WireGuard adds 60 bytes of overhead for IPv4, 80 bytes for IPv6

3. **Addresses**
   - At least one address must be configured
   - Must be valid IPv4 or IPv6 CIDR notation
   - Typically /32 for IPv4 and /128 for IPv6 node addresses

#### Peer Configuration

For each peer in the WireGuard configuration:

1. **Public Key**
   - Must be set and non-zero
   - Must be a valid Curve25519 public key
   - Used for cryptographic identity and routing

2. **AllowedIPs**
   - At least one allowed IP range must be specified
   - Must be valid CIDR notation
   - IPv4 prefix length: 0-32
   - IPv6 prefix length: 0-128
   - Defines which IP addresses can be routed through this peer

3. **Persistent Keepalive**
   - Optional field (0 = disabled)
   - If set, should be reasonable (typically 0-300 seconds)
   - Common values: 25 seconds for NAT traversal
   - Values above 300 seconds may indicate misconfiguration

## Tailscale-Specific Enhancements

While maintaining WireGuard compliance, Tailscale adds several features:

### 1. Coordination Server
- Manages key distribution and network topology
- Eliminates manual configuration of peers
- Provides centralized policy enforcement

### 2. DERP (Designated Encrypted Relay for Packets)
- Fallback relay system when direct connections aren't possible
- Encrypted relay preserves end-to-end encryption
- Automatic selection of optimal relay servers

### 3. NAT Traversal
- Automatic hole-punching for direct connections
- Works behind most NATs and firewalls
- No port forwarding configuration required

### 4. MagicDNS
- Automatic DNS resolution for tailnet nodes
- Uses `.ts.net` domain suffix
- No manual DNS configuration needed

### 5. Key Management
- Automatic key rotation
- Network lock (tailnet key authority) for additional security
- No manual key distribution

## Testing

The compliance validation is thoroughly tested in `wgengine/wgcfg/compliance_test.go`:

```bash
# Run compliance tests
./tool/go test ./wgengine/wgcfg -run TestValidateWireGuardCompliance

# Run all wgcfg tests including compliance
./tool/go test ./wgengine/wgcfg/...
```

## Validation API

### ValidateWireGuardCompliance()

Validates a complete WireGuard configuration:

```go
cfg := &wgcfg.Config{
    PrivateKey: privateKey,
    Addresses: []netip.Prefix{
        netip.MustParsePrefix("100.64.0.1/32"),
    },
    Peers: []wgcfg.Peer{
        {
            PublicKey: peerKey,
            AllowedIPs: []netip.Prefix{
                netip.MustParsePrefix("100.64.0.0/10"),
            },
        },
    },
}

if err := cfg.ValidateWireGuardCompliance(); err != nil {
    log.Fatalf("Configuration is not WireGuard compliant: %v", err)
}
```

### ValidateAddresses()

Validates node addresses:

```go
addresses := []netip.Prefix{
    netip.MustParsePrefix("100.64.0.1/32"),
    netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
}

if err := wgcfg.ValidateAddresses(addresses); err != nil {
    log.Fatalf("Invalid addresses: %v", err)
}
```

## Error Handling

Compliance errors are returned as `*ComplianceError` with detailed information:

```go
type ComplianceError struct {
    Field   string  // The configuration field that failed validation
    Message string  // Detailed error message
}
```

Example error messages:
- `WireGuard compliance error in PrivateKey: private key must be set`
- `WireGuard compliance error in Peers[0].AllowedIPs: at least one allowed IP must be specified`
- `WireGuard compliance error in MTU: MTU 500 is outside reasonable range (576-65535)`

## References

- [WireGuard Protocol Specification](https://www.wireguard.com/protocol/)
- [WireGuard Formal Verification](https://www.wireguard.com/formal-verification/)
- [Tailscale Documentation](https://tailscale.com/kb/)
- [WireGuard® is a registered trademark of Jason A. Donenfeld](https://www.wireguard.com/)

## Compliance Checklist

- [x] Protocol version 1 enforcement
- [x] Private key validation
- [x] Public key validation for all peers
- [x] AllowedIPs CIDR validation
- [x] MTU range validation
- [x] Persistent keepalive validation
- [x] Address configuration validation
- [x] Comprehensive test coverage
- [x] Error reporting with detailed messages

## Network-Specific Configuration

For specific tailnet configurations (e.g., custom domains like `prairiedog-godzilla.ts.net`), the same WireGuard compliance rules apply. The validation ensures that regardless of the tailnet domain or MagicDNS configuration, all WireGuard protocol requirements are met.

### Example for Custom Tailnet Domain

```go
// Configuration for any tailnet domain (e.g., prairiedog-godzilla.ts.net)
// follows the same WireGuard compliance rules
cfg := &wgcfg.Config{
    Name:       "node-name.prairiedog-godzilla.ts.net.",
    PrivateKey: privateKey,
    Addresses: []netip.Prefix{
        netip.MustParsePrefix("100.64.0.1/32"),
    },
    // ... rest of configuration
}

// Validation is domain-agnostic
if err := cfg.ValidateWireGuardCompliance(); err != nil {
    log.Fatal(err)
}
```

The WireGuard protocol operates at the network layer and is independent of DNS names or tailnet domains. All tailnet configurations must meet the same WireGuard protocol standards.
