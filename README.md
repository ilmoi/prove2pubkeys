# Solana Keypair Generation and HD Wallet Derivation

This TypeScript project demonstrates how to generate a random Solana keypair and derive two public keys using HD wallet derivation paths.

## Features

- Generate a random Solana keypair using `@solana/web3.js`
- Derive public keys using HD wallet paths:
  - `m/44'/501'/0'/0'` (first derived key)
  - `m/44'/501'/0'/1'` (second derived key)
- Display private key and public keys in multiple formats

## Installation

```bash
npm install
```

## Usage

### Development (with ts-node)
```bash
npm run dev
```

### Production Build
```bash
npm run build
npm start
```

## Output

The script will output:
- Master private key (Base64 and Hex formats)
- Master public key
- Two derived public keys using the specified HD wallet paths

## Dependencies

- `@solana/web3.js` - Solana Web3.js library
- `ed25519-hd-key` - HD wallet derivation for Ed25519 keys
- `typescript` - TypeScript compiler
- `ts-node` - TypeScript execution for development

## Project Structure

```
src/
  index.ts          # Main script
package.json        # Dependencies and scripts
tsconfig.json       # TypeScript configuration
README.md          # This file
```
# prove2pubkeys
