#pragma once
#include <vector>
#include <string>

class EntropyProcessor {
public:
    static std::vector<unsigned char> deriveEd25519Seed(const std::vector<unsigned char>& entropy);
    static std::vector<unsigned char> sha256Hash(const std::vector<unsigned char>& data);
};
