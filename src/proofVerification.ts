import { join } from "path";
import * as snarkjs from "snarkjs";

/**
 * Verifies a proof using the compiled circuit with real ZK proof verification
 */
export async function verifyProof(
  proof: any,
  publicSignals: any
): Promise<boolean> {
  try {
    // Load the verification key
    const vkeyPath = join(__dirname, "../verification_key.json");
    const fs = require("fs");
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));

    console.log("Verifying real ZK proof using snarkjs.groth16.verify");
    console.log("Proof structure:", Object.keys(proof));
    console.log(
      "Public signals:",
      publicSignals.map((x: any) => x.toString())
    );
    console.log("Verification key curve:", vkey.curve);

    // Verify the proof using snarkjs with the loaded vkey object
    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

    console.log("Proof verification result:", isValid);
    return isValid;
  } catch (error) {
    console.error("Error verifying proof:", error);
    return false;
  }
}

/**
 * Verifies a proof using a simple witness check (alternative approach)
 */
export function verifyWitness(witness: any[]): boolean {
  try {
    // The witness should contain the output signal at the end
    // For our circuit, the output is the 'valid' signal
    const outputIndex = witness.length - 1;
    const outputValue = witness[outputIndex];

    console.log(`  Output value: ${outputValue}`);
    console.log(`  Output type: ${typeof outputValue}`);
    console.log(`  Is BigInt: ${typeof outputValue === "bigint"}`);

    // The circuit should output 1 if the proof is valid
    // This means the derived keys match the input keys
    const isValid =
      outputValue === 1n || outputValue === 1 || outputValue.toString() === "1";

    console.log(`  Is valid: ${isValid}`);

    if (!isValid) {
      console.log(
        `  ❌ Circuit output is ${outputValue}, expected 1. Proof is invalid.`
      );
      console.log(`  This means the derived keys don't match the input keys.`);
    } else {
      console.log(`  ✅ Circuit output is 1. Proof is valid!`);
    }

    return isValid;
  } catch (error) {
    console.error("Error verifying witness:", error);
    return false;
  }
}

/**
 * Simple verification that checks if the derived keys match the expected keys
 */
export async function verifyKeyDerivation(
  seed: bigint[],
  expectedPubkey1: bigint[],
  expectedPubkey2: bigint[],
  path1: number[],
  path2: number[]
): Promise<boolean> {
  try {
    // Import the key derivation function
    const { deriveTwoPublicKeys } = require("./keyDerivation");

    // Derive the keys
    const { pubkey1, pubkey2 } = await deriveTwoPublicKeys(seed, path1, path2);

    // Check if they match
    const match1 = pubkey1.every(
      (val: bigint, i: number) => val === expectedPubkey1[i]
    );
    const match2 = pubkey2.every(
      (val: bigint, i: number) => val === expectedPubkey2[i]
    );

    return match1 && match2;
  } catch (error) {
    console.error("Error verifying key derivation:", error);
    return false;
  }
}
