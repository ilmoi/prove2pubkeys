import { readFileSync } from "fs";
import { join } from "path";
import * as snarkjs from "snarkjs";

/**
 * Generates a proof using the compiled circuit with real ZK proof generation
 */
export async function generateProof(
  seed: bigint[],
  pubkey1: bigint[],
  pubkey2: bigint[],
  path1: number[],
  path2: number[]
): Promise<{ proof: any; publicSignals: any }> {
  try {
    // Load the compiled circuit files
    const wasmPath = join(__dirname, "../2pubkeys_js/2pubkeys.wasm");
    const zkeyPath = join(__dirname, "../2pubkeys_final.zkey");

    // Prepare input for the circuit
    const input = {
      seed: seed.map((x) => x.toString()),
      pubkey1: pubkey1.map((x) => x.toString()),
      pubkey2: pubkey2.map((x) => x.toString()),
      path1: path1.map((x) => x.toString()),
      path2: path2.map((x) => x.toString()),
    };

    console.log(
      "Generating real ZK proof with input:",
      JSON.stringify(input, null, 2)
    );

    // Generate proof using snarkjs
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath
    );

    console.log("Generated real ZK proof successfully");
    console.log("Proof structure:", Object.keys(proof));
    console.log(
      "Public signals:",
      publicSignals.map((x: any) => x.toString())
    );

    return { proof, publicSignals };
  } catch (error) {
    console.error("Error generating proof:", error);
    throw error;
  }
}

/**
 * Generates a proof using the witness calculator (alternative approach)
 */
export async function generateProofWithWitness(
  seed: bigint[],
  pubkey1: bigint[],
  pubkey2: bigint[],
  path1: number[],
  path2: number[]
): Promise<{ witness: any }> {
  try {
    // Import the witness calculator
    const witnessCalculator = require("../2pubkeys_js/witness_calculator.js");
    const wasmBuffer = readFileSync(
      join(__dirname, "../2pubkeys_js/2pubkeys.wasm")
    );

    // Prepare input for the circuit
    const input = {
      seed: seed.map((x) => x.toString()),
      pubkey1: pubkey1.map((x) => x.toString()),
      pubkey2: pubkey2.map((x) => x.toString()),
      path1: path1.map((x) => x.toString()),
      path2: path2.map((x) => x.toString()),
    };

    console.log(
      "Generating witness with input:",
      JSON.stringify(input, null, 2)
    );

    // Create witness calculator
    const wc = await witnessCalculator(wasmBuffer);

    // Calculate witness
    const witness = await wc.calculateWitness(input, 0);

    return { witness };
  } catch (error) {
    console.error("Error generating witness:", error);
    throw error;
  }
}
