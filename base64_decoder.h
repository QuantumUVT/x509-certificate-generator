#pragma once
#include <string>
#include <vector>

class Base64Decoder {
public:
    static std::vector<unsigned char> decode(const std::string& input);
};
