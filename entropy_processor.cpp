#include "entropy_processor.h"
#include <openssl/sha.h>
#include <stdexcept>

std::vector<unsigned char> EntropyProcessor::sha256Hash(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        throw std::runtime_error("Cannot hash empty data");
    }

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    
    if (!SHA256(data.data(), data.size(), hash.data())) {
        throw std::runtime_error("SHA256 hashing failed");
    }
    
    return hash;
}

std::vector<unsigned char> EntropyProcessor::deriveEd25519Seed(const std::vector<unsigned char>& entropy) {
    if (entropy.size() < 16) {
        throw std::runtime_error("Insufficient entropy: need at least 16 bytes from QKD keys");
    }

    // Use SHA256 to derive a deterministic 32-byte seed from the entropy
    auto hash = sha256Hash(entropy);
    
    // Ed25519 seed is exactly 32 bytes, which matches SHA256 output
    return hash;
}
