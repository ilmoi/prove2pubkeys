pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

// Template for simplified key derivation
template KeyDerive() {
    signal input seed[8]; // 64 bytes seed
    signal input path[4]; // 4 path components: [44', 501', account', change']
    signal output private_key[8]; // 64 bytes private key
    
    // Use Poseidon hash for deterministic key derivation
    // This is a simplified approach - real BIP32 uses HMAC-SHA512
    component hasher = Poseidon(12);
    
    // Hash seed with path components
    for (var i = 0; i < 8; i++) {
        hasher.inputs[i] <== seed[i];
    }
    hasher.inputs[8] <== path[0];  // 44'
    hasher.inputs[9] <== path[1];  // 501'
    hasher.inputs[10] <== path[2]; // account'
    hasher.inputs[11] <== path[3]; // change'
    
    // Generate private key deterministically
    for (var i = 0; i < 8; i++) {
        private_key[i] <== hasher.out + i;
    }
    
    log("hasher.out", hasher.out);
}

// Template for Ed25519 key generation from private key
template Ed25519KeyGen() {
    signal input private_key[8]; // 64 bytes private key
    signal output public_key[4]; // 32 bytes public key (4 * 8 bytes)
    
    // Simplified Ed25519 key generation using Poseidon
    component key_hasher = Poseidon(8);
    
    for (var i = 0; i < 8; i++) {
        key_hasher.inputs[i] <== private_key[i];
    }
    
    // Generate public key from private key
    // This is simplified - real Ed25519 uses scalar multiplication on curve
    public_key[0] <== key_hasher.out;
    public_key[1] <== key_hasher.out + 1;
    public_key[2] <== key_hasher.out + 2;
    public_key[3] <== key_hasher.out + 3;
    
    log("key_hasher.out", key_hasher.out);
}

// Main circuit template
template Prove2PubKeys() {
    // Inputs
    signal input seed[8]; // 64 bytes seed
    signal input pubkey1[4]; // First public key (32 bytes)
    signal input pubkey2[4]; // Second public key (32 bytes)
    signal input path1[4]; // First derivation path [44', 501', 0', 0']
    signal input path2[4]; // Second derivation path [44', 501', 0', 1']
    
    // Outputs
    signal output valid; // 1 if both pubkeys derive from same seed
    
    // Derive private keys from seed using both paths
    component derive1 = KeyDerive();
    component derive2 = KeyDerive();
    
    for (var i = 0; i < 8; i++) {
        derive1.seed[i] <== seed[i];
        derive2.seed[i] <== seed[i];
    }
    
    for (var i = 0; i < 4; i++) {
        derive1.path[i] <== path1[i];
        derive2.path[i] <== path2[i];
    }
    
    // Generate public keys from derived private keys
    component keygen1 = Ed25519KeyGen();
    component keygen2 = Ed25519KeyGen();
    
    for (var i = 0; i < 8; i++) {
        keygen1.private_key[i] <== derive1.private_key[i];
        keygen2.private_key[i] <== derive2.private_key[i];
    }
    
    // Verify that derived public keys match input public keys
    component eq1[4];
    component eq2[4];

    for (var i = 0; i < 4; i++) {
        eq1[i] = IsEqual();
        eq2[i] = IsEqual();
        
        eq1[i].in[0] <== keygen1.public_key[i];
        eq1[i].in[1] <== pubkey1[i];

        log("eq1[i].in[0]", eq1[i].in[0]);
        log("eq1[i].in[1]", eq1[i].in[1]);
        
        eq2[i].in[0] <== keygen2.public_key[i];
        eq2[i].in[1] <== pubkey2[i];

        log("eq2[i].in[0]", eq2[i].in[0]);
        log("eq2[i].in[1]", eq2[i].in[1]);
    }
    
    // Check if all equality results are 1
    // For pubkey1: eq1[0] * eq1[1] * eq1[2] * eq1[3] should be 1
    // For pubkey2: eq2[0] * eq2[1] * eq2[2] * eq2[3] should be 1
    // Final result: both should be 1
    
    signal temp1;
    signal temp2;
    signal temp3;
    signal temp4;
    signal temp5;
    signal temp6;
    
    temp1 <== eq1[0].out * eq1[1].out;
    temp2 <== temp1 * eq1[2].out;
    temp3 <== temp2 * eq1[3].out;
    
    temp4 <== eq2[0].out * eq2[1].out;
    temp5 <== temp4 * eq2[2].out;
    temp6 <== temp5 * eq2[3].out;
    
    valid <== temp3 * temp6;

    log("valid", valid);
    
    // Ensure valid is exactly 1 (not 0)
    valid === 1;
}

// Main component
component main = Prove2PubKeys();