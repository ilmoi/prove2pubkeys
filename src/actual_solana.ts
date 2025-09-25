// derive-solana.ts
import * as crypto from "crypto";

/*
  Steps implemented:
  1) master = HMAC-SHA512(key="ed25519 seed", seed)
     masterKey = master.slice(0,32)
     masterChain = master.slice(32)
  2) For each hardened index i:
     data = 0x00 || parentKey(32) || ser32(i + 0x80000000)
     I = HMAC-SHA512(parentChain, data)
     childKey = I[0..31], childChain = I[32..63]
  3) After final private key (32 bytes) -> wrap in PKCS8 DER for Ed25519
  4) createPrivateKey + createPublicKey (Node crypto) -> export SPKI DER -> last 32 bytes is raw Ed25519 public key
  5) base58 encode public key -> Solana pubkey
*/

// === helpers ===
function hmacSha512(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("sha512", key).update(data).digest();
}

function ser32(i: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(i >>> 0, 0);
  return b;
}

function parsePath(path: string): number[] {
  if (!path.startsWith("m/")) throw new Error("path must start with m/");
  const parts = path.slice(2).split("/");
  return parts.map((p) => {
    const hardened = p.endsWith("'");
    const idx = parseInt(hardened ? p.slice(0, -1) : p, 10);
    if (!Number.isFinite(idx)) throw new Error("bad path part: " + p);
    return hardened ? (idx + 0x80000000) >>> 0 : idx >>> 0;
  });
}

// base58 (Bitcoin alphabet) — no libs
const ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(buf: Buffer): string {
  // convert big-endian bytes to base58
  let x = BigInt(0);
  for (const b of buf) {
    x = (x << BigInt(8)) + BigInt(b);
  }
  let out = "";
  while (x > 0) {
    const mod = x % BigInt(58);
    out = ALPH[Number(mod)] + out;
    x = x / BigInt(58);
  }
  // leading zero bytes -> '1'
  for (let i = 0; i < buf.length && buf[i] === 0; i++) out = "1" + out;
  return out || "1";
}

// === SLIP-0010 ed25519 derive ===
function getMasterKeyFromSeed(seed: Buffer) {
  const I = hmacSha512(Buffer.from("ed25519 seed", "utf8"), seed);
  return { key: I.slice(0, 32), chainCode: I.slice(32, 64) };
}

function deriveChild(key: Buffer, chain: Buffer, index: number) {
  // only hardened supported (index >= 0x80000000)
  const data = Buffer.concat([Buffer.from([0x00]), key, ser32(index)]);
  const I = hmacSha512(chain, data);
  return { key: I.slice(0, 32), chainCode: I.slice(32, 64) };
}

function derivePath(seed: Buffer, path: string) {
  const indices = parsePath(path);
  let { key, chainCode } = getMasterKeyFromSeed(seed);
  for (const idx of indices) {
    if ((idx & 0x80000000) === 0) {
      throw new Error(
        "ed25519 SLIP-0010 only supports hardened derivation; path must use '"
      );
    }
    ({ key, chainCode } = deriveChild(key, chainCode, idx));
  }
  return { priv: key, chainCode };
}

// === wrap 32-byte ed25519 private key into PKCS8 DER ===
// PKCS8 prefix for Ed25519 private key with 32-byte seed:
// hex: 302e020100300506032b657004220420
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SPKI public key prefix (to parse exported spki): 302a300506032b6570032100 (32 byte pub follows)
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519PublicFromPrivateKeyBytes(privKey32: Buffer): Buffer {
  // build PKCS8 DER: prefix || privKey32
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, privKey32]);
  const privateKeyObject = crypto.createPrivateKey({
    key: pkcs8,
    format: "der",
    type: "pkcs8",
  });
  const publicKeyObject = crypto.createPublicKey(privateKeyObject);
  const spkiDer = publicKeyObject.export({
    format: "der",
    type: "spki",
  }) as Buffer;

  // last 32 bytes of SPKI DER are the raw public key (for Ed25519)
  // double-check length; if prefix matches, slice after prefix length
  if (
    spkiDer.slice(0, SPKI_ED25519_PREFIX.length).equals(SPKI_ED25519_PREFIX)
  ) {
    return spkiDer.slice(
      SPKI_ED25519_PREFIX.length,
      SPKI_ED25519_PREFIX.length + 32
    );
  } else {
    // fallback: return last 32 bytes
    return spkiDer.slice(spkiDer.length - 32);
  }
}

// === Example use ===
function deriveSolanaPubkeyFromSeed(
  seedHexOrBuf: string | Buffer,
  path: string
) {
  const seed =
    typeof seedHexOrBuf === "string"
      ? Buffer.from(seedHexOrBuf, "hex")
      : seedHexOrBuf;
  const { priv } = derivePath(seed, path); // priv is 32 bytes
  const pub = ed25519PublicFromPrivateKeyBytes(priv);
  return { pubkeyBytes: pub, pubkeyBase58: base58Encode(pub) };
}

// === Demo ===
// replace this seed with your seed (hex). Use your own seed bytes.
// Example: a 64-byte BIP39 seed hex string (replace with your actual seed).
const exampleSeedHex = "000102030405060708090a0b0c0d0e0f".repeat(4); // 64 bytes (demo only)
const p0 = deriveSolanaPubkeyFromSeed(exampleSeedHex, "m/44'/501'/0'/0'");
const p1 = deriveSolanaPubkeyFromSeed(exampleSeedHex, "m/44'/501'/0'/1'");

console.log("path m/44'/501'/0'/0' ->", p0.pubkeyBase58);
console.log("path m/44'/501'/0'/1' ->", p1.pubkeyBase58);

// Also export raw bytes if you need them:
// console.log("raw pub0:", p0.pubkeyBytes.toString("hex"));
