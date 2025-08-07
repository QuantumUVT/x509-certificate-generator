#include "certificate_generator.h"
#include <filesystem>
#include <iostream>
#include <cstdio>
#include <random>
#include <chrono>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

void CertificateGenerator::ensureDirectoryExists(const std::string& filepath) {
    std::filesystem::path path(filepath);
    std::filesystem::path directory = path.parent_path();
    
    if (!directory.empty() && !std::filesystem::exists(directory)) {
        std::filesystem::create_directories(directory);
    }
}

long CertificateGenerator::generateRandomSerial() {
    // Use a combination of random number generator and timestamp for uniqueness
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<long> dis(1000000, 999999999);
    
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    // Combine random number with timestamp (modulo to prevent overflow)
    return (dis(gen) + (timestamp % 1000000)) % 999999999 + 1;
}

X509_NAME_ptr CertificateGenerator::buildSubjectName(const CertificateConfig& config) {
    X509_NAME* raw_name = X509_NAME_new();
    if (!raw_name) {
        throw std::runtime_error("Failed to create X509_NAME");
    }
    
    X509_NAME_ptr name(raw_name);
    
    auto addEntry = [&](const std::string& field, const std::string& value) {
        if (!value.empty()) {
            if (!X509_NAME_add_entry_by_txt(name.get(), field.c_str(), MBSTRING_ASC,
                                          (unsigned char*)value.c_str(), -1, -1, 0)) {
                throw std::runtime_error("Failed to add " + field + " to certificate subject");
            }
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

void CertificateGenerator::generateCertificate(EVP_PKEY* pkey, const CertificateConfig& config) {
    X509* raw_cert = X509_new();
    if (!raw_cert) {
        throw std::runtime_error("Failed to create X509 certificate");
    }
    
    X509_ptr cert(raw_cert);
    

    if (!X509_set_version(cert.get(), 2)) {
        throw std::runtime_error("Failed to set certificate version");
    }
    
    // Set random serial number
    long serial = generateRandomSerial();
    if (!ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial)) {
        throw std::runtime_error("Failed to set certificate serial number");
    }
    
    // Set validity period
    if (!X509_gmtime_adj(X509_get_notBefore(cert.get()), 0)) {
        throw std::runtime_error("Failed to set certificate notBefore");
    }
    if (!X509_gmtime_adj(X509_get_notAfter(cert.get()), (long)60 * 60 * 24 * config.days)) {
        throw std::runtime_error("Failed to set certificate notAfter");
    }
    
    // Set public key
    if (!X509_set_pubkey(cert.get(), pkey)) {
        throw std::runtime_error("Failed to set certificate public key");
    }
    
    // Build and set subject name
    auto name = buildSubjectName(config);
    if (!X509_set_subject_name(cert.get(), name.get())) {
        throw std::runtime_error("Failed to set certificate subject name");
    }
    
    // For self-signed certificate, issuer = subject
    if (!X509_set_issuer_name(cert.get(), name.get())) {
        throw std::runtime_error("Failed to set certificate issuer name");
    }
    
    // Sign the certificate
    if (!X509_sign(cert.get(), pkey, nullptr)) {
        throw std::runtime_error("Failed to sign certificate");
    }
    
    // Write certificate file
    std::string cert_filename = config.prefix + "_cert.pem";
    ensureDirectoryExists(cert_filename);
    
    FILE* cert_file = fopen(cert_filename.c_str(), "wb");
    if (!cert_file) {
        throw std::runtime_error("Failed to open certificate file for writing: " + cert_filename);
    }
    
    if (!PEM_write_X509(cert_file, cert.get())) {
        fclose(cert_file);
        throw std::runtime_error("Failed to write certificate to file");
    }
    fclose(cert_file);
    
    // Write private key file
    std::string key_filename = config.prefix + "_key.pem";
    ensureDirectoryExists(key_filename);
    
    FILE* key_file = fopen(key_filename.c_str(), "wb");
    if (!key_file) {
        throw std::runtime_error("Failed to open key file for writing: " + key_filename);
    }
    
    if (!PEM_write_PrivateKey(key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(key_file);
        throw std::runtime_error("Failed to write private key to file");
    }
    fclose(key_file);
    
    std::cout << "Saved " << cert_filename << " and " << key_filename 
              << " (Serial: " << serial << ")" << std::endl;
}
