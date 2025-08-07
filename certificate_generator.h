#pragma once
#include "certificate_config.h"
#include "openssl_wrappers.h"

class CertificateGenerator {
public:
    static void generateCertificate(EVP_PKEY* pkey, const CertificateConfig& config);
    
private:
    static X509_NAME_ptr buildSubjectName(const CertificateConfig& config);
    static void ensureDirectoryExists(const std::string& filepath);
    static long generateRandomSerial();
};
