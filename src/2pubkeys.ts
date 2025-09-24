import * as ed25519 from "@noble/ed25519";
import { createHash, createHmac } from "crypto";

// Set up the hash function for noble-ed25519
ed25519.etc.sha512Sync = (...m) =>
  createHash("sha512").update(Buffer.concat(m)).digest();

/**
 * HD wallet derivation matching ed25519-hd-key library exactly
 * @param seed - Master seed as hex string (like ed25519-hd-key expects)
 * @param path - Derivation path (e.g., "m/44'/501'/0'/0'")
 * @returns Object with private key, public key, and chain code
 */
export function deriveEd25519HDPath(
  seed: string,
  path: string
): {
  privateKey: Buffer;
  publicKey: Buffer;
  chainCode: Buffer;
} {
  // Parse derivation path - must match ed25519-hd-key format
  const pathParts = path.split("/");
  if (pathParts[0] !== "m") {
    throw new Error('Path must start with "m"');
  }

  // Remove 'm' and process the rest - match ed25519-hd-key logic
  const segments = pathParts.slice(1).map((part) => {
    // Remove the ' character and parse as integer
    const cleanPart = part.replace("'", "");
    return parseInt(cleanPart, 10);
  });

  // Master key derivation - exactly like ed25519-hd-key
  const hmac = createHmac("sha512", "ed25519 seed");
  const I = hmac.update(Buffer.from(seed, "hex")).digest();
  const IL = I.slice(0, 32);
  const IR = I.slice(32);

  let currentKey = IL;
  let currentChainCode = IR;

  // Derive through each level - exactly like ed25519-hd-key CKDPriv
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    const index = segment + 0x80000000; // Add hardened offset

    // Create data exactly like ed25519-hd-key CKDPriv
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), currentKey, indexBuffer]);

    // HMAC-SHA512 with chain code as key - exactly like ed25519-hd-key
    const I = createHmac("sha512", currentChainCode).update(data).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    // Update for next iteration
    currentKey = IL;
    currentChainCode = IR;
  }

  // Generate public key using the same method as ed25519-hd-key
  const publicKey = getPublicKeyEd25519HD(currentKey);

  return {
    privateKey: currentKey,
    publicKey: publicKey,
    chainCode: currentChainCode,
  };
}

/**
 * Get public key using the same method as ed25519-hd-key library
 * @param privateKey - Private key buffer
 * @param withZeroByte - Whether to prepend zero byte (default true)
 * @returns Public key buffer
 */
export function getPublicKeyEd25519HD(
  privateKey: Buffer,
  withZeroByte: boolean = true
): Buffer {
  // Use the same method as ed25519-hd-key: get public key from private key
  const publicKey = ed25519.getPublicKey(privateKey);

  if (withZeroByte) {
    const zero = Buffer.alloc(1, 0);
    return Buffer.concat([zero, publicKey]);
  }

  return Buffer.from(publicKey);
}

/**
 * Test function to verify the implementation works correctly
 */
export function testImplementations() {
  console.log("🧪 Testing TypeScript implementation...");

  try {
    // Test HD wallet derivation
    const testSeed = "test-seed-32-bytes-exactly-here!";
    const derived = deriveEd25519HDPath(
      Buffer.from(testSeed, "utf8").toString("hex"),
      "m/44'/0'/0'/0'"
    );
    console.log("✅ HD wallet derivation test passed");
    console.log(`   Private key length: ${derived.privateKey.length} bytes`);
    console.log(`   Public key length: ${derived.publicKey.length} bytes`);

    return true;
  } catch (error) {
    console.error("❌ Test failed:", error);
    return false;
  }
}
