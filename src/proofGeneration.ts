import { readFileSync } from "fs";
import { join } from "path";
import * as snarkjs from "snarkjs";

/**
 * Generates a proof using the compiled circuit
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
    const zkeyPath = join(__dirname, "../2pubkeys.r1cs"); // We'll need to generate this

    // Prepare input for the circuit
    const input = {
      seed: seed.map((x) => x.toString()),
      pubkey1: pubkey1.map((x) => x.toString()),
      pubkey2: pubkey2.map((x) => x.toString()),
      path1: path1.map((x) => x.toString()),
      path2: path2.map((x) => x.toString()),
    };

    console.log("Generating proof with input:", JSON.stringify(input, null, 2));

    // Generate proof
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath
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
