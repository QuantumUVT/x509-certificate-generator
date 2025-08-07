#pragma once
#include "certificate_config.h"
#include "openssl_wrappers.h"
#include <vector>

class KeyGenerator {
public:
    static EVP_PKEY_ptr generateEd25519KeyFromSeed(const std::vector<unsigned char>& seed);
};
