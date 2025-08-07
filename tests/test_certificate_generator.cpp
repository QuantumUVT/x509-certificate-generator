#include "certificate_generator.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <fstream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <chrono>
#include <thread>

// Test fixture for CertificateGenerator tests
class CertificateGeneratorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a test directory for certificates
        test_dir = "test_certs";
        std::filesystem::create_directories(test_dir);
        
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        // Create a test ED25519 key pair
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (pctx) {
            EVP_PKEY_keygen_init(pctx);
            EVP_PKEY* raw_key = nullptr;
            EVP_PKEY_keygen(pctx, &raw_key);
            test_key.reset(raw_key);
            EVP_PKEY_CTX_free(pctx);
        }
    }
    
    void TearDown() override {
        // Clean up test files
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
        
        // Clean up any generated certificate files
        for (const auto& file : generated_files) {
            if (std::filesystem::exists(file)) {
                std::filesystem::remove(file);
            }
        }
        
        EVP_cleanup();
        ERR_free_strings();
    }
    
    CertificateConfig createDefaultConfig() {
        CertificateConfig config;
        config.country = "US";
        config.state = "California";
        config.locality = "San Francisco";
        config.organization = "Test Corp";
        config.organizational_unit = "Test Unit";
        config.common_name = "test.example.com";
        config.days = 365;
        config.prefix = test_dir + "/test";
        return config;
    }
    
    bool fileExists(const std::string& filename) {
        return std::filesystem::exists(filename);
    }
    
    bool isValidPEMCertificate(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "r");
        if (!file) return false;
        
        X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
        fclose(file);
        
        if (cert) {
            X509_free(cert);
            return true;
        }
        return false;
    }
    
    bool isValidPEMPrivateKey(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "r");
        if (!file) return false;
        
        EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        fclose(file);
        
        if (key) {
            EVP_PKEY_free(key);
            return true;
        }
        return false;
    }
    
    long getCertificateSerial(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "r");
        if (!file) return -1;
        
        X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
        fclose(file);
        
        if (!cert) return -1;
        
        ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(cert);
        long serial = ASN1_INTEGER_get(serial_asn1);
        X509_free(cert);
        return serial;
    }
    
    std::string test_dir;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> test_key{nullptr, EVP_PKEY_free};
    std::vector<std::string> generated_files;
    CertificateGenerator generator;
};

// Tests for ensureDirectoryExists method
TEST_F(CertificateGeneratorTest, EnsureDirectoryExists_CreatesNestedDirectories) {
    std::string nested_path = test_dir + "/deeply/nested/path/file.pem";
    
    generator.ensureDirectoryExists(nested_path);
    
    EXPECT_TRUE(std::filesystem::exists(test_dir + "/deeply/nested/path"));
}

TEST_F(CertificateGeneratorTest, EnsureDirectoryExists_HandlesExistingDirectory) {
    std::string existing_path = test_dir + "/existing/file.pem";
    std::filesystem::create_directories(test_dir + "/existing");
    
    EXPECT_NO_THROW(generator.ensureDirectoryExists(existing_path));
    EXPECT_TRUE(std::filesystem::exists(test_dir + "/existing"));
}

TEST_F(CertificateGeneratorTest, EnsureDirectoryExists_HandlesRootLevelFile) {
    std::string root_file = "root_file.pem";
    
    EXPECT_NO_THROW(generator.ensureDirectoryExists(root_file));
}

TEST_F(CertificateGeneratorTest, EnsureDirectoryExists_HandlesEmptyPath) {
    std::string empty_path = "";
    
    EXPECT_NO_THROW(generator.ensureDirectoryExists(empty_path));
}

// Tests for generateRandomSerial method
TEST_F(CertificateGeneratorTest, GenerateRandomSerial_ReturnsValidRange) {
    long serial = generator.generateRandomSerial();
    
    EXPECT_GT(serial, 0);
    EXPECT_LE(serial, 999999999);
}

TEST_F(CertificateGeneratorTest, GenerateRandomSerial_GeneratesUniqueSerials) {
    std::set<long> serials;
    const int num_tests = 1000;
    
    for (int i = 0; i < num_tests; ++i) {
        long serial = generator.generateRandomSerial();
        serials.insert(serial);
    }
    
    // Should have high uniqueness (allow for small collision rate)
    EXPECT_GT(serials.size(), num_tests * 0.95);
}

TEST_F(CertificateGeneratorTest, GenerateRandomSerial_ChangesOverTime) {
    long serial1 = generator.generateRandomSerial();
    
    // Sleep to ensure timestamp difference
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    long serial2 = generator.generateRandomSerial();
    
    // While not guaranteed to be different due to randomness, 
    // they should be different most of the time
    EXPECT_NE(serial1, serial2);
}

// Tests for buildSubjectName method
TEST_F(CertificateGeneratorTest, BuildSubjectName_WithAllFields) {
    CertificateConfig config = createDefaultConfig();
    
    auto name = generator.buildSubjectName(config);
    
    ASSERT_NE(name.get(), nullptr);
    
    // Verify the name has entries
    int entry_count = X509_NAME_entry_count(name.get());
    EXPECT_GT(entry_count, 0);
}

TEST_F(CertificateGeneratorTest, BuildSubjectName_WithEmptyFields) {
    CertificateConfig config;
    config.common_name = ""; // Should default to "QKD-ED25519"
    
    auto name = generator.buildSubjectName(config);
    
    ASSERT_NE(name.get(), nullptr);
    
    // Should still create a name with default CN
    int entry_count = X509_NAME_entry_count(name.get());
    EXPECT_GT(entry_count, 0);
}

TEST_F(CertificateGeneratorTest, BuildSubjectName_WithOnlyCommonName) {
    CertificateConfig config;
    config.common_name = "test.example.com";
    
    auto name = generator.buildSubjectName(config);
    
    ASSERT_NE(name.get(), nullptr);
    int entry_count = X509_NAME_entry_count(name.get());
    EXPECT_EQ(entry_count, 1);
}

TEST_F(CertificateGeneratorTest, BuildSubjectName_DefaultsCommonNameWhenEmpty) {
    CertificateConfig config;
    // Leave common_name empty
    
    auto name = generator.buildSubjectName(config);
    
    ASSERT_NE(name.get(), nullptr);
    
    // Check that CN is set to default value
    char* cn_str = X509_NAME_oneline(name.get(), nullptr, 0);
    std::string name_str(cn_str);
    OPENSSL_free(cn_str);
    
    EXPECT_THAT(name_str, ::testing::HasSubstr("QKD-ED25519"));
}

TEST_F(CertificateGeneratorTest, BuildSubjectName_WithSpecialCharacters) {
    CertificateConfig config;
    config.common_name = "test@example.com";
    config.organization = "Test Corp, Inc.";
    config.locality = "San Francisco/Oakland";
    
    auto name = generator.buildSubjectName(config);
    
    ASSERT_NE(name.get(), nullptr);
    int entry_count = X509_NAME_entry_count(name.get());
    EXPECT_GT(entry_count, 0);
}

// Tests for generateCertificate method - Happy Path
TEST_F(CertificateGeneratorTest, GenerateCertificate_CreatesValidFiles) {
    ASSERT_NE(test_key.get(), nullptr) << "Test key creation failed";
    
    CertificateConfig config = createDefaultConfig();
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists(config.prefix + "_cert.pem"));
    EXPECT_TRUE(fileExists(config.prefix + "_key.pem"));
    EXPECT_TRUE(isValidPEMCertificate(config.prefix + "_cert.pem"));
    EXPECT_TRUE(isValidPEMPrivateKey(config.prefix + "_key.pem"));
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_SetsCorrectValidityPeriod) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.days = 730; // 2 years
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    generator.generateCertificate(test_key.get(), config);
    
    // Read the certificate and check validity period
    FILE* file = fopen((config.prefix + "_cert.pem").c_str(), "r");
    ASSERT_NE(file, nullptr);
    
    X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    ASSERT_NE(cert, nullptr);
    
    // Check that certificate is currently valid
    int result = X509_cmp_current_time(X509_get_notBefore(cert));
    EXPECT_LE(result, 0); // notBefore should be <= current time
    
    result = X509_cmp_current_time(X509_get_notAfter(cert));
    EXPECT_GE(result, 0); // notAfter should be >= current time
    
    X509_free(cert);
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_SetsUniqueSerialNumbers) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config1 = createDefaultConfig();
    config1.prefix = test_dir + "/cert1";
    generated_files.push_back(config1.prefix + "_cert.pem");
    generated_files.push_back(config1.prefix + "_key.pem");
    
    CertificateConfig config2 = createDefaultConfig();
    config2.prefix = test_dir + "/cert2";
    generated_files.push_back(config2.prefix + "_cert.pem");
    generated_files.push_back(config2.prefix + "_key.pem");
    
    generator.generateCertificate(test_key.get(), config1);
    generator.generateCertificate(test_key.get(), config2);
    
    long serial1 = getCertificateSerial(config1.prefix + "_cert.pem");
    long serial2 = getCertificateSerial(config2.prefix + "_cert.pem");
    
    EXPECT_NE(serial1, serial2);
    EXPECT_GT(serial1, 0);
    EXPECT_GT(serial2, 0);
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithMinimalConfig) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config;
    config.days = 30;
    config.prefix = test_dir + "/minimal";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists(config.prefix + "_cert.pem"));
    EXPECT_TRUE(fileExists(config.prefix + "_key.pem"));
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithLongValidityPeriod) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.days = 3650; // 10 years
    config.prefix = test_dir + "/long_validity";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists(config.prefix + "_cert.pem"));
    EXPECT_TRUE(isValidPEMCertificate(config.prefix + "_cert.pem"));
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithZeroDayValidity) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.days = 0; // Expires immediately
    config.prefix = test_dir + "/zero_days";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists(config.prefix + "_cert.pem"));
    EXPECT_TRUE(isValidPEMCertificate(config.prefix + "_cert.pem"));
}

// Tests for error conditions
TEST_F(CertificateGeneratorTest, GenerateCertificate_ThrowsWithNullKey) {
    CertificateConfig config = createDefaultConfig();
    
    EXPECT_THROW(generator.generateCertificate(nullptr, config), std::runtime_error);
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_HandlesInvalidDirectoryPath) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    // Create a path that should work but test directory creation
    config.prefix = "non_existent_dir/deeply/nested/cert";
    generated_files.push_back("non_existent_dir/deeply/nested/cert_cert.pem");
    generated_files.push_back("non_existent_dir/deeply/nested/cert_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists("non_existent_dir/deeply/nested/cert_cert.pem"));
    EXPECT_TRUE(fileExists("non_existent_dir/deeply/nested/cert_key.pem"));
    
    // Cleanup
    if (std::filesystem::exists("non_existent_dir")) {
        std::filesystem::remove_all("non_existent_dir");
    }
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithVeryLongFieldValues) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config;
    config.country = "US";
    config.state = std::string(100, 'A'); // Very long state name
    config.locality = std::string(100, 'B'); // Very long locality
    config.organization = std::string(100, 'C'); // Very long org name
    config.organizational_unit = std::string(100, 'D'); // Very long OU
    config.common_name = std::string(50, 'E') + ".example.com"; // Long CN
    config.days = 365;
    config.prefix = test_dir + "/long_fields";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists(config.prefix + "_cert.pem"));
    EXPECT_TRUE(isValidPEMCertificate(config.prefix + "_cert.pem"));
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithUnicodeCharacters) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config;
    config.country = "JP";
    config.locality = "東京"; // Tokyo in Japanese
    config.organization = "テスト会社"; // Test Company in Japanese  
    config.common_name = "test.example.com";
    config.days = 365;
    config.prefix = test_dir + "/unicode";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    // This might throw or succeed depending on OpenSSL configuration
    // We test that it doesn't crash
    EXPECT_NO_FATAL_FAILURE(generator.generateCertificate(test_key.get(), config));
}

// Edge case tests
TEST_F(CertificateGeneratorTest, GenerateCertificate_OverwritesExistingFiles) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.prefix = test_dir + "/overwrite_test";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    // Generate first certificate
    generator.generateCertificate(test_key.get(), config);
    
    // Get modification time of first certificate
    auto first_time = std::filesystem::last_write_time(config.prefix + "_cert.pem");
    
    // Wait a bit to ensure different timestamp
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Generate second certificate (should overwrite)
    generator.generateCertificate(test_key.get(), config);
    
    auto second_time = std::filesystem::last_write_time(config.prefix + "_cert.pem");
    
    EXPECT_NE(first_time, second_time);
    EXPECT_TRUE(isValidPEMCertificate(config.prefix + "_cert.pem"));
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithEmptyPrefix) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.prefix = ""; // Empty prefix
    generated_files.push_back("_cert.pem");
    generated_files.push_back("_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists("_cert.pem"));
    EXPECT_TRUE(fileExists("_key.pem"));
}

TEST_F(CertificateGeneratorTest, GenerateCertificate_WithSpecialCharactersInPrefix) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.prefix = test_dir + "/cert-with-dashes_and_underscores.test";
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    
    EXPECT_TRUE(fileExists(config.prefix + "_cert.pem"));
    EXPECT_TRUE(fileExists(config.prefix + "_key.pem"));
}

// Performance and stress tests
TEST_F(CertificateGeneratorTest, GenerateCertificate_MultipleConsecutiveCalls) {
    ASSERT_NE(test_key.get(), nullptr);
    
    const int num_certs = 10;
    std::vector<std::string> cert_files, key_files;
    
    for (int i = 0; i < num_certs; ++i) {
        CertificateConfig config = createDefaultConfig();
        config.prefix = test_dir + "/batch_" + std::to_string(i);
        
        cert_files.push_back(config.prefix + "_cert.pem");
        key_files.push_back(config.prefix + "_key.pem");
        generated_files.push_back(config.prefix + "_cert.pem");
        generated_files.push_back(config.prefix + "_key.pem");
        
        EXPECT_NO_THROW(generator.generateCertificate(test_key.get(), config));
    }
    
    // Verify all certificates were created and are unique
    std::set<long> serials;
    for (const auto& cert_file : cert_files) {
        EXPECT_TRUE(fileExists(cert_file));
        EXPECT_TRUE(isValidPEMCertificate(cert_file));
        
        long serial = getCertificateSerial(cert_file);
        EXPECT_GT(serial, 0);
        serials.insert(serial);
    }
    
    // All serials should be unique
    EXPECT_EQ(serials.size(), num_certs);
    
    // Verify all key files
    for (const auto& key_file : key_files) {
        EXPECT_TRUE(fileExists(key_file));
        EXPECT_TRUE(isValidPEMPrivateKey(key_file));
    }
}

// Integration test - verify certificate properties
TEST_F(CertificateGeneratorTest, GenerateCertificate_VerifiesCertificateProperties) {
    ASSERT_NE(test_key.get(), nullptr);
    
    CertificateConfig config = createDefaultConfig();
    config.days = 90;
    generated_files.push_back(config.prefix + "_cert.pem");
    generated_files.push_back(config.prefix + "_key.pem");
    
    generator.generateCertificate(test_key.get(), config);
    
    // Load and verify certificate properties
    FILE* file = fopen((config.prefix + "_cert.pem").c_str(), "r");
    ASSERT_NE(file, nullptr);
    
    X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    ASSERT_NE(cert, nullptr);
    
    // Verify version (should be 3, stored as 2)
    EXPECT_EQ(X509_get_version(cert), 2);
    
    // Verify serial number is in expected range
    ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(cert);
    long serial = ASN1_INTEGER_get(serial_asn1);
    EXPECT_GT(serial, 0);
    EXPECT_LE(serial, 999999999);
    
    // Verify subject and issuer are the same (self-signed)
    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME* issuer = X509_get_issuer_name(cert);
    EXPECT_EQ(X509_NAME_cmp(subject, issuer), 0);
    
    // Verify public key matches our test key
    EVP_PKEY* cert_pubkey = X509_get_pubkey(cert);
    ASSERT_NE(cert_pubkey, nullptr);
    
    EXPECT_EQ(EVP_PKEY_cmp(test_key.get(), cert_pubkey), 1);
    
    EVP_PKEY_free(cert_pubkey);
    X509_free(cert);
}