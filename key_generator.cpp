#include "key_generator.h"
#include <openssl/evp.h>
#include <stdexcept>

EVP_PKEY_ptr KeyGenerator::generateEd25519KeyFromSeed(const std::vector<unsigned char>& seed) {
    if (seed.size() < 32) {
        throw std::runtime_error("Ed25519 seed must be at least 32 bytes");
    }

    EVP_PKEY* raw_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), 32);
    if (!raw_pkey) {
        throw std::runtime_error("Failed to create Ed25519 private key from seed");
    }

    return EVP_PKEY_ptr(raw_pkey);
}
