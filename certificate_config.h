#pragma once
#include <string>
#include <vector>

struct CertificateConfig {
    // cppcheck-suppress unusedStructMember
    std::vector<std::string> keys;
    std::string prefix = "qkd_ed25519";
    int days = 365;
    // cppcheck-suppress unusedStructMember
    std::string country;
    // cppcheck-suppress unusedStructMember
    std::string state;
    // cppcheck-suppress unusedStructMember
    std::string locality;
    // cppcheck-suppress unusedStructMember
    std::string organization;
    // cppcheck-suppress unusedStructMember
    std::string organizational_unit;
    // cppcheck-suppress unusedStructMember
    std::string common_name;
};
