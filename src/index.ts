import { Keypair, PublicKey } from "@solana/web3.js";
import * as ed25519 from "ed25519-hd-key";
import { deriveEd25519HDPath, testImplementations } from "./2pubkeys";

async function main() {
  console.log("🔑 Solana Keypair Generation and HD Wallet Derivation");
  console.log("=".repeat(60));

  // First, test our TypeScript implementations
  console.log("\n🧪 Testing TypeScript implementations...");
  const testPassed = testImplementations();
  if (!testPassed) {
    console.error("❌ Tests failed, exiting...");
    return;
  }

  // Generate a deterministic keypair using a fixed seed
  const seed = "prove2pubkeys-deterministic-seed-2024";
  const seedBuffer = Buffer.from(seed, "utf8");

  // Create keypair from deterministic seed
  const keypair = Keypair.fromSeed(seedBuffer.slice(0, 32)); // Use first 32 bytes as seed
  const privateKey = keypair.secretKey;
  const masterPublicKey = keypair.publicKey;

  console.log("\n📋 Master Keypair:");
  console.log(
    `Private Key (Base58): ${Buffer.from(privateKey).toString("base64")}`
  );
  console.log(`Private Key (Hex): ${Buffer.from(privateKey).toString("hex")}`);
  console.log(`Master Public Key: ${masterPublicKey.toString()}`);

  // For HD wallet derivation, we'll use the same deterministic seed
  // Note: Solana uses Ed25519, so we'll derive using the standard HD wallet approach
  const hdSeed = seedBuffer;

  try {
    // Derive first public key using path m/44'/501'/0'/0'
    const derivedKey1 = ed25519.derivePath(
      "m/44'/501'/0'/0'",
      hdSeed.toString("hex")
    );
    const pubkey1 = new PublicKey(derivedKey1.key);

    // Derive second public key using path m/44'/501'/0'/1'
    const derivedKey2 = ed25519.derivePath(
      "m/44'/501'/0'/1'",
      hdSeed.toString("hex")
    );
    const pubkey2 = new PublicKey(derivedKey2.key);

    console.log("\n🔗 Derived Public Keys (using ed25519-hd-key):");
    console.log(`Path m/44'/501'/0'/0': ${pubkey1.toString()}`);
    console.log(`Path m/44'/501'/0'/1': ${pubkey2.toString()}`);

    // Now test our exact ed25519-hd-key implementation
    console.log(
      "\n-----------------------------------------🔧 Testing exact ed25519-hd-key TypeScript implementation..."
    );

    // Test what ed25519-hd-key is doing internally
    const testDerived = ed25519.derivePath(
      "m/44'/501'/0'/0'",
      hdSeed.toString("hex")
    );

    // Use our exact ed25519-hd-key implementation
    const customDerived0 = deriveEd25519HDPath(
      hdSeed.toString("hex"),
      "m/44'/501'/0'/0'"
    );
    const customDerived1 = deriveEd25519HDPath(
      hdSeed.toString("hex"),
      "m/44'/501'/0'/1'"
    );

    // // Debug: Show what ed25519-hd-key actually returns
    // console.log("\n🔍 ed25519-hd-key Library Analysis:");
    // console.log(
    //   `ed25519-hd-key .key field: ${testDerived.key.toString(
    //     "hex"
    //   )} (this is the PRIVATE KEY)`
    // );
    // console.log(
    //   `ed25519-hd-key .chainCode field: ${testDerived.chainCode.toString(
    //     "hex"
    //   )}`
    // );

    // // The ed25519-hd-key library doesn't return the public key directly
    // // We need to derive it from the private key
    // const ed25519PublicKey = ed25519.getPublicKey(testDerived.key);
    // console.log(
    //   `Derived public key from ed25519-hd-key private key: ${ed25519PublicKey.toString(
    //     "hex"
    //   )}`
    // );

    console.log("\n🔍 Our Implementation Analysis:");
    console.log(
      `Our private key: ${customDerived0.privateKey.toString("hex")}`
    );
    console.log(
      `Our public key (with zero byte): ${customDerived0.publicKey.toString(
        "hex"
      )}`
    );
    console.log(
      `Our public key (without zero byte): ${customDerived0.publicKey
        .slice(1)
        .toString("hex")}`
    );

    // Create public keys from ed25519-hd-key private keys for proper comparison
    const ed25519Pubkey1 = new PublicKey(ed25519.getPublicKey(testDerived.key));
    const ed25519Pubkey2 = new PublicKey(
      ed25519.getPublicKey(
        ed25519.derivePath("m/44'/501'/0'/1'", hdSeed.toString("hex")).key
      )
    );

    // Convert our implementation to Solana PublicKey format
    const exactPubkey1 = new PublicKey(customDerived0.publicKey.slice(1)); // Remove zero byte
    const exactPubkey2 = new PublicKey(customDerived1.publicKey.slice(1)); // Remove zero byte

    console.log("\n🔗 Derived Public Keys (Solana format):");
    console.log(`Path m/44'/501'/0'/0': ${exactPubkey1.toString()}`);
    console.log(`Path m/44'/501'/0'/1': ${exactPubkey2.toString()}`);

    // Compare the results using the correct public keys
    console.log("\n🔍 Public Key Comparison:");
    console.log(`ed25519-hd-key Child 0: ${ed25519Pubkey1.toString()}`);
    console.log(`Exact implementation Child 0: ${exactPubkey1.toString()}`);
    console.log(
      `Match: ${
        ed25519Pubkey1.toString() === exactPubkey1.toString() ? "✅" : "❌"
      }`
    );

    console.log(`ed25519-hd-key Child 1: ${ed25519Pubkey2.toString()}`);
    console.log(`Exact implementation Child 1: ${exactPubkey2.toString()}`);
    console.log(
      `Match: ${
        ed25519Pubkey2.toString() === exactPubkey2.toString() ? "✅" : "❌"
      }`
    );

    // Compare private keys and chain codes
    const privateKeyMatch =
      testDerived.key.toString("hex") ===
      customDerived0.privateKey.toString("hex");
    const chainCodeMatch =
      testDerived.chainCode.toString("hex") ===
      customDerived0.chainCode.toString("hex");

    console.log("\n🔍 Cryptographic Values Comparison:");
    console.log(`Private key match: ${privateKeyMatch ? "✅" : "❌"}`);
    console.log(`Chain code match: ${chainCodeMatch ? "✅" : "❌"}`);

    if (privateKeyMatch && chainCodeMatch) {
      console.log(
        "\n🎉 SUCCESS: Custom implementation perfectly matches ed25519-hd-key library!"
      );
    } else {
      console.log("\n❌ Mismatch detected in cryptographic values");
    }
  } catch (error) {
    console.error("❌ Error during HD wallet derivation:", error);
  }
}

// Run the main function
main().catch(console.error);
