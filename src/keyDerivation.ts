import { buildPoseidon } from "circomlibjs";

let poseidon: any = null;

/**
 * Initialize the Poseidon hash function
 */
async function initPoseidon() {
  if (!poseidon) {
    poseidon = await buildPoseidon();
  }
  return poseidon;
}

/**
 * Derives a private key from seed and path using the same logic as the circuit
 * This matches the KeyDerive template in the circuit
 */
export async function derivePrivateKey(
  seed: bigint[],
  path: number[]
): Promise<bigint[]> {
  const poseidonFn = await initPoseidon();

  // Convert seed to the format expected by Poseidon (12 inputs)
  const inputs: bigint[] = [];

  // Add seed (8 elements)
  for (let i = 0; i < 8; i++) {
    inputs.push(seed[i]);
  }

  // Add path components (4 elements)
  for (let i = 0; i < 4; i++) {
    inputs.push(BigInt(path[i]));
  }

  // Hash using Poseidon (12 inputs)
  const hash = poseidonFn(inputs);

  // Convert hash to BigInt
  const hashBigInt = BigInt(
    "0x" +
      Array.from(hash)
        .map((b: any) => b.toString(16).padStart(2, "0"))
        .join("")
  );

  // Generate private key deterministically (8 elements)
  const privateKey: bigint[] = [];
  for (let i = 0; i < 8; i++) {
    privateKey.push(hashBigInt + BigInt(i));
  }

  return privateKey;
}

/**
 * Generates a public key from private key using the same logic as the circuit
 * This matches the Ed25519KeyGen template in the circuit
 */
export async function generatePublicKey(
  privateKey: bigint[]
): Promise<bigint[]> {
  const poseidonFn = await initPoseidon();

  // Hash private key using Poseidon (8 inputs)
  const hash = poseidonFn(privateKey);

  // Convert hash to BigInt
  const hashBigInt = BigInt(
    "0x" +
      Array.from(hash)
        .map((b: any) => b.toString(16).padStart(2, "0"))
        .join("")
  );

  // Generate public key (4 elements)
  const publicKey: bigint[] = [];
  for (let i = 0; i < 4; i++) {
    publicKey.push(hashBigInt + BigInt(i));
  }

  return publicKey;
}

/**
 * Derives two public keys from a seed using two different paths
 * This matches the main Prove2PubKeys circuit logic
 */
export async function deriveTwoPublicKeys(
  seed: bigint[],
  path1: number[],
  path2: number[]
): Promise<{ pubkey1: bigint[]; pubkey2: bigint[] }> {
  // Derive private keys
  const privateKey1 = await derivePrivateKey(seed, path1);
  const privateKey2 = await derivePrivateKey(seed, path2);

  // Generate public keys
  const pubkey1 = await generatePublicKey(privateKey1);
  const pubkey2 = await generatePublicKey(privateKey2);

  return { pubkey1, pubkey2 };
}

/**
 * Converts a string seed to bigint array (8 elements of 64-bit chunks)
 */
export function stringToSeed(seedString: string): bigint[] {
  const seed: bigint[] = [];
  const bytes = new TextEncoder().encode(seedString);

  // Pad to 64 bytes (8 * 8 bytes)
  const paddedBytes = new Uint8Array(64);
  paddedBytes.set(bytes.slice(0, 64));

  // Convert to 8 bigint chunks
  for (let i = 0; i < 8; i++) {
    const chunk = new Uint8Array(8);
    chunk.set(paddedBytes.slice(i * 8, (i + 1) * 8));

    let value = 0n;
    for (let j = 0; j < 8; j++) {
      value = (value << 8n) + BigInt(chunk[j]);
    }
    seed.push(value);
  }

  return seed;
}
