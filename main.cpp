#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <memory>
#include <filesystem>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/err.h>

class Base64 {
public:
    static std::vector<unsigned char> decode(const std::string& input) {
        BIO* bio = BIO_new_mem_buf(input.c_str(), -1);
        BIO* b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        
        std::vector<unsigned char> result(input.length());
        int decoded_size = BIO_read(bio, result.data(), input.length());
        
        BIO_free_all(bio);
        
        if (decoded_size < 0) {
            throw std::runtime_error("Base64 decode failed");
        }
        
        result.resize(decoded_size);
        return result;
    }
};

class CertificateGenerator {
private:
    struct CertConfig {
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

    static void ensureDirectoryExists(const std::string& filepath) {
        std::filesystem::path path(filepath);
        std::filesystem::path directory = path.parent_path();
        
        if (!directory.empty() && !std::filesystem::exists(directory)) {
            std::filesystem::create_directories(directory);
        }
    }

public:
    static EVP_PKEY* generateEd25519KeyFromSeed(const std::vector<unsigned char>& seed) {
        if (seed.size() < 32) {
            throw std::runtime_error("Ed25519 seed must be at least 32 bytes");
        }

        return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), 32);
    }

    static X509_NAME* buildSubjectName(const CertConfig& config) {
        X509_NAME* name = X509_NAME_new();
        if (!name) {
            throw std::runtime_error("Failed to create X509_NAME");
        }
        
        auto addEntry = [&](const std::string& field, const std::string& value) {
            if (!value.empty()) {
                X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC,
                                         (unsigned char*)value.c_str(), -1, -1, 0);
            }
        };
        
        addEntry("C", config.country);
        addEntry("ST", config.state);
        addEntry("L", config.locality);
        addEntry("O", config.organization);
        addEntry("OU", config.organizational_unit);
        addEntry("CN", config.common_name.empty() ? "QKD-ED25519" : config.common_name);
        
        return name;
    }

    static void generateCertificate(EVP_PKEY* pkey, const CertConfig& config) {
        X509* cert = X509_new();
        if (!cert) {
            throw std::runtime_error("Failed to create X509 certificate");
        }
        
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * config.days);
        X509_set_pubkey(cert, pkey);
        
        X509_NAME* name = buildSubjectName(config);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        
        if (!X509_sign(cert, pkey, nullptr)) {
            X509_free(cert);
            X509_NAME_free(name);
            throw std::runtime_error("Failed to sign certificate");
        }
        
        std::string cert_filename = config.prefix + "_cert.pem";
        ensureDirectoryExists(cert_filename);
        FILE* cert_file = fopen(cert_filename.c_str(), "wb");
        if (!cert_file) {
            X509_free(cert);
            X509_NAME_free(name);
            throw std::runtime_error("Failed to open certificate file for writing");
        }
        
        if (!PEM_write_X509(cert_file, cert)) {
            fclose(cert_file);
            X509_free(cert);
            X509_NAME_free(name);
            throw std::runtime_error("Failed to write certificate");
        }
        fclose(cert_file);
        
        std::string key_filename = config.prefix + "_key.pem";
        ensureDirectoryExists(key_filename);
        FILE* key_file = fopen(key_filename.c_str(), "wb");
        if (!key_file) {
            X509_free(cert);
            X509_NAME_free(name);
            throw std::runtime_error("Failed to open key file for writing");
        }
        
        if (!PEM_write_PrivateKey(key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            fclose(key_file);
            X509_free(cert);
            X509_NAME_free(name);
            throw std::runtime_error("Failed to write private key");
        }
        fclose(key_file);
        
        std::cout << "Saved " << cert_filename << " and " << key_filename << std::endl;
        
        X509_free(cert);
        X509_NAME_free(name);
    }

    static void printUsage(const char* program_name) {
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

    static int run(int argc, char* argv[]) {
        CertConfig config;
        
        static struct option long_options[] = {
            {"key", required_argument, 0, 'k'},
            {"prefix", required_argument, 0, 'p'},
            {"days", required_argument, 0, 'd'},
            {"C", required_argument, 0, 'c'},
            {"ST", required_argument, 0, 's'},
            {"L", required_argument, 0, 'l'},
            {"O", required_argument, 0, 'o'},
            {"OU", required_argument, 0, 'u'},
            {"CN", required_argument, 0, 'n'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        
        int option_index = 0;
        int c;
        
        while ((c = getopt_long(argc, argv, "k:p:d:c:s:l:o:u:n:h", long_options, &option_index)) != -1) {
            switch (c) {
                case 'k':
                    config.keys.push_back(std::string(optarg));
                    break;
                case 'p':
                    config.prefix = std::string(optarg);
                    break;
                case 'd':
                    config.days = std::atoi(optarg);
                    break;
                case 'c':
                    config.country = std::string(optarg);
                    break;
                case 's':
                    config.state = std::string(optarg);
                    break;
                case 'l':
                    config.locality = std::string(optarg);
                    break;
                case 'o':
                    config.organization = std::string(optarg);
                    break;
                case 'u':
                    config.organizational_unit = std::string(optarg);
                    break;
                case 'n':
                    config.common_name = std::string(optarg);
                    break;
                case 'h':
                    printUsage(argv[0]);
                    return 0;
                default:
                    printUsage(argv[0]);
                    return 1;
            }
        }
        
        if (config.keys.empty()) {
            std::cerr << "Error: At least one --key argument is required\n";
            printUsage(argv[0]);
            return 1;
        }
        
        try {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
            
            std::vector<unsigned char> entropy;
            for (const auto& key : config.keys) {
                auto decoded = Base64::decode(key);
                entropy.insert(entropy.end(), decoded.begin(), decoded.end());
            }

            if (entropy.size() < 32) {
                throw std::runtime_error("Not enough entropy: need at least 32 bytes from QKD keys");
            }

            std::vector<unsigned char> seed(entropy.begin(), entropy.begin() + 32);
            auto pkey = generateEd25519KeyFromSeed(seed);
            generateCertificate(pkey, config);
            EVP_PKEY_free(pkey);

            return 0;
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
};

int main(int argc, char* argv[]) {
    return CertificateGenerator::run(argc, argv);
}
