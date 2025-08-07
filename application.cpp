#include "application.h"
#include "command_line_parser.h"
#include "base64_decoder.h"
#include "entropy_processor.h"
#include "key_generator.h"
#include "certificate_generator.h"
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>

void Application::initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void Application::cleanupOpenSSL() {
    // Clean up OpenSSL (available in OpenSSL 1.1.0+)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
#else
    EVP_cleanup();
    ERR_free_strings();
#endif
}

int Application::run(int argc, char* argv[]) {
    CertificateConfig config;
    
    // Parse command line arguments
    int parse_result = CommandLineParser::parseArguments(argc, argv, config);
    if (parse_result != -1) {
        return parse_result; // Early return for help or error
    }
    
    try {
        initializeOpenSSL();
        
        // Collect entropy from all QKD keys
        std::vector<unsigned char> entropy;
        for (const auto& key : config.keys) {
            try {
                auto decoded = Base64Decoder::decode(key);
                entropy.insert(entropy.end(), decoded.begin(), decoded.end());
            } catch (const std::exception& e) {
                std::cerr << "Error decoding key '" << key.substr(0, 20) << "...': " 
                         << e.what() << std::endl;
                cleanupOpenSSL();
                return 1;
            }
        }

        // Derive Ed25519 seed using SHA256
        auto seed = EntropyProcessor::deriveEd25519Seed(entropy);
        
        // Generate Ed25519 key from seed
        auto pkey = KeyGenerator::generateEd25519KeyFromSeed(seed);
        
        // Generate certificate
        CertificateGenerator::generateCertificate(pkey.get(), config);
        
        cleanupOpenSSL();
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        cleanupOpenSSL();
        return 1;
    }
}
