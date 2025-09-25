import { deriveTwoPublicKeys, stringToSeed } from "./keyDerivation";
import { generateProofWithWitness } from "./proofGeneration";
import { verifyKeyDerivation, verifyWitness } from "./proofVerification";

/**
 * Main function that demonstrates the complete flow:
 * 1. Derives 2 fake Solana pubkeys from a seed
 * 2. Generates a proof using the circuit
 * 3. Verifies the proof using witness verification (verifyWitness)
 *
 * NOTE: This version uses witness verification which only checks the circuit output,
 * not the cryptographic proof. For proper ZK proof verification, use index2.ts
 */
async function main() {
  console.log("🚀 Starting Prove2PubKeys demonstration...\n");

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
    const { witness } = await generateProofWithWitness(
      seed,
      pubkey1,
      pubkey2,
      path1,
      path2
    );

    console.log("✅ Witness generated successfully");
    console.log(`  Witness length: ${witness.length}`);
    console.log(`  Output value: ${witness[witness.length - 1]}`);
    console.log();

    // Step 4: Verify the proof
    console.log("✅ Step 4: Verifying proof...");
    const proofValid = verifyWitness(witness);
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
