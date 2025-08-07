#include "usage_printer.h"
#include <iostream>

void UsagePrinter::printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Generate Ed25519 X.509 cert from QKD keys\n\n"
              << "Options:\n"
              << "  --key KEY        Base64-encoded QKD key (can be used multiple times)\n"
              << "  --prefix PREFIX  Filename prefix for cert and key (default: qkd_ed25519)\n"
              << "  --days DAYS      Certificate validity in days (default: 365)\n"
              << "  --C COUNTRY      Country Name (e.g., RO)\n"
              << "  --ST STATE       State or Province Name\n"
              << "  --L LOCALITY     Locality Name\n"
              << "  --O ORG          Organization Name\n"
              << "  --OU ORG_UNIT    Organizational Unit Name\n"
              << "  --CN COMMON_NAME Common Name\n"
              << "  --help           Show this help message\n";
}
