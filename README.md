# Prove2PubKeys Circuit

A Circom circuit that proves two Solana public keys originate from the same seed using HD wallet derivation paths.

## Overview

The circuit takes:
- **seed**: 64 bytes master seed
- **pubkey1 & pubkey2**: Two 32-byte public keys to verify
- **path1 & path2**: Two BIP44 derivation paths (e.g., `m/44'/501'/0'/0'` and `m/44'/501'/0'/1'`)

And outputs:
- **valid**: 1 if both public keys derive from the same seed, 0 otherwise

## Usage

### Compile the Circuit
```bash
circom 2pubkeys.circom --r1cs --wasm --sym
```

### Generate Witness
```bash
cd 2pubkeys_js
node generate_witness.js 2pubkeys.wasm ../input.json witness.wtns
```

## Input Format

The circuit expects decimal string inputs in `input.json`:

```json
{
  "seed": ["1234567890123456", "2345678901234567", ...],
  "pubkey1": ["1111111111111111", "2222222222222222", ...],
  "pubkey2": ["5555555555555555", "6666666666666666", ...],
  "path1": [44, 501, 0, 0],
  "path2": [44, 501, 0, 1]
}
```

## Simplifications vs Real Solana Key Derivation

This circuit makes several simplifications compared to real Solana key derivation:

### Current Implementation (Simplified)
- **Hash Function**: Uses Poseidon hash instead of HMAC-SHA512
- **Key Derivation**: Simplified BIP32 derivation using Poseidon
- **Ed25519**: Simplified key generation using Poseidon instead of elliptic curve operations
- **Path Handling**: Basic path components without hardened derivation support

### Real Solana Key Derivation
- **Hash Function**: Uses HMAC-SHA512 for BIP32 key derivation
- **Key Derivation**: Full BIP32 specification with proper chain code handling
- **Ed25519**: Real scalar multiplication on the Ed25519 curve
- **Path Handling**: Support for hardened derivation (') and proper path parsing
- **Security**: Proper key material handling and side-channel resistance

## Important Notes

- Use **decimal strings**, not hex strings in the input
- Each value should be a 64-bit integer (0 to 2^64-1)
- This is a simplified implementation for demonstration purposes
- Real Solana key derivation uses HMAC-SHA512 and Ed25519 curve operations
# prove2pubkeys_v2
