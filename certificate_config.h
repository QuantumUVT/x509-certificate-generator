#pragma once
#include <string>
#include <vector>

struct CertificateConfig {
    std::vector<std::string> keys;
    std::string prefix = "qkd_ed25519";
    int days = 365;
    std::string country;
    std::string state;
    std::string locality;
    std::string organization;
    std::string organizational_unit;
    std::string common_name;
};
