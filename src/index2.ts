import { deriveTwoPublicKeys, stringToSeed } from "./keyDerivation";
import { generateProof } from "./proofGeneration";
import { verifyKeyDerivation, verifyProof } from "./proofVerification";

/**
 * Main function that demonstrates the complete flow using verifyProof:
 * 1. Derives 2 fake Solana pubkeys from a seed
 * 2. Generates a proof using the circuit
 * 3. Verifies the proof using snarkjs.groth16.verify (instead of witness verification)
 *
 * This version uses the proper ZK proof verification instead of just checking the witness output.
 *
 * DIFFERENCE FROM index.ts:
 * - Uses generateProof() instead of generateProofWithWitness()
 * - Uses verifyProof() instead of verifyWitness()
 * - Performs cryptographic proof verification instead of just witness output checking
 */
async function main() {
  console.log(
    "🚀 Starting Prove2PubKeys demonstration (with verifyProof)...\n"
  );

  try {
    // Step 1: Create a seed and derive two public keys
    console.log("📝 Step 1: Deriving public keys from seed...");
    const seedString = "my-secret-seed-for-solana-keys-12345678901234567890";
    const seed = stringToSeed(seedString);

    const path1 = [44, 501, 0, 0]; // First derivation path
    const path2 = [44, 501, 0, 1]; // Second derivation path

    const { pubkey1, pubkey2 } = await deriveTwoPublicKeys(seed, path1, path2);

    console.log("✅ Derived public keys:");
    console.log(
      "  Pubkey1:",
      pubkey1.map((x) => x.toString())
    );
    console.log(
      "  Pubkey2:",
      pubkey2.map((x) => x.toString())
    );
    console.log("  Path1:", path1);
    console.log("  Path2:", path2);
    console.log();

    // Step 2: Verify key derivation works correctly
    console.log("🔍 Step 2: Verifying key derivation...");
    const derivationValid = await verifyKeyDerivation(
      seed,
      pubkey1,
      pubkey2,
      path1,
      path2
    );
    console.log(
      `✅ Key derivation verification: ${
        derivationValid ? "PASSED" : "FAILED"
      }\n`
    );

    // Step 3: Generate proof using the circuit
    console.log("🔐 Step 3: Generating proof with circuit...");
    const { proof, publicSignals } = await generateProof(
      seed,
      pubkey1,
      pubkey2,
      path1,
      path2
    );

    console.log("✅ Proof generated successfully");
    console.log(`  Proof object keys: ${Object.keys(proof)}`);
    console.log(`  Public signals length: ${publicSignals.length}`);
    console.log(
      `  Public signals: ${publicSignals.map((x: any) => x.toString())}`
    );
    console.log();

    // Step 4: Verify the proof using snarkjs.groth16.verify
    console.log("✅ Step 4: Verifying proof with verifyProof...");
    const proofValid = await verifyProof(proof, publicSignals);
    console.log(`✅ Proof verification: ${proofValid ? "PASSED" : "FAILED"}\n`);

    // Summary
    console.log("📊 Summary:");
    console.log(
      `  ✅ Key derivation: ${derivationValid ? "PASSED" : "FAILED"}`
    );
    console.log(`  ✅ Proof generation: SUCCESS`);
    console.log(`  ✅ Proof verification: ${proofValid ? "PASSED" : "FAILED"}`);

    if (derivationValid && proofValid) {
      console.log(
        "\n🎉 All tests passed! The circuit correctly proves that both public keys derive from the same seed."
      );
    } else if (derivationValid && !proofValid) {
      console.log("\n⚠️  Key derivation works, but proof verification failed.");
      console.log(
        "   This means there's a mismatch between our TypeScript derivation"
      );
      console.log(
        "   and the circuit's field arithmetic. The circuit expects the"
      );
      console.log("   derived keys to exactly match the input keys.");
    } else {
      console.log("\n❌ Some tests failed. Please check the implementation.");
    }
  } catch (error) {
    console.error("❌ Error in main function:", error);
    process.exit(1);
  }
}

// Run the demonstration
if (require.main === module) {
  main().catch(console.error);
}

export { main };
