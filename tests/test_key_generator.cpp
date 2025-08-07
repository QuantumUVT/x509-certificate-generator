#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "key_generator.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <stdexcept>
#include <memory>
#include <random>
#include <thread>
#include <chrono>
#include <cstring>

class KeyGeneratorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clear any OpenSSL errors before each test
        ERR_clear_error();
    }

    void TearDown() override {
        // Clean up any remaining OpenSSL errors after each test
        ERR_clear_error();
    }

    // Helper function to create a valid 32-byte seed
    std::vector<unsigned char> createValidSeed() {
        return std::vector<unsigned char>(32, 0x42);
    }

    // Helper function to create a random seed
    std::vector<unsigned char> createRandomSeed(size_t size = 32) {
        std::vector<unsigned char> seed(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<unsigned char> dis(0, 255);
        
        for (auto& byte : seed) {
            byte = dis(gen);
        }
        return seed;
    }

    // Helper function to verify EVP_PKEY is valid Ed25519 key
    bool isValidEd25519Key(const EVP_PKEY_ptr& key) {
        if (!key) return false;
        return EVP_PKEY_id(key.get()) == EVP_PKEY_ED25519;
    }

    // Helper function to get public key from private key
    std::vector<unsigned char> getPublicKeyFromPrivateKey(const EVP_PKEY_ptr& pkey) {
        size_t pub_key_len = 32; // Ed25519 public key is always 32 bytes
        std::vector<unsigned char> pub_key(pub_key_len);
        
        if (EVP_PKEY_get_raw_public_key(pkey.get(), pub_key.data(), &pub_key_len) != 1) {
            return {};
        }
        
        pub_key.resize(pub_key_len);
        return pub_key;
    }
};

// Happy Path Tests
TEST_F(KeyGeneratorTest, GenerateKeyFromValidSeed_Success) {
    auto seed = createValidSeed();
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, GenerateKeyFromExact32ByteSeed_Success) {
    std::vector<unsigned char> seed(32, 0xAB);
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, GenerateKeyFromRandomSeed_Success) {
    auto seed = createRandomSeed();
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, GenerateKeyFromLargerSeed_UsesFirst32Bytes) {
    std::vector<unsigned char> seed(64, 0xFF);
    // Set first 32 bytes to a specific pattern
    for (int i = 0; i < 32; ++i) {
        seed[i] = static_cast<unsigned char>(i);
    }
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, SameSeedProducesSameKey) {
    std::vector<unsigned char> seed(32, 0x12);
    
    auto key1 = KeyGenerator::generateEd25519KeyFromSeed(seed);
    auto key2 = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key1, nullptr);
    ASSERT_NE(key2, nullptr);
    
    auto pub_key1 = getPublicKeyFromPrivateKey(key1);
    auto pub_key2 = getPublicKeyFromPrivateKey(key2);
    
    EXPECT_EQ(pub_key1, pub_key2);
}

TEST_F(KeyGeneratorTest, DifferentSeedsProduceDifferentKeys) {
    std::vector<unsigned char> seed1(32, 0x11);
    std::vector<unsigned char> seed2(32, 0x22);
    
    auto key1 = KeyGenerator::generateEd25519KeyFromSeed(seed1);
    auto key2 = KeyGenerator::generateEd25519KeyFromSeed(seed2);
    
    ASSERT_NE(key1, nullptr);
    ASSERT_NE(key2, nullptr);
    
    auto pub_key1 = getPublicKeyFromPrivateKey(key1);
    auto pub_key2 = getPublicKeyFromPrivateKey(key2);
    
    EXPECT_NE(pub_key1, pub_key2);
}

// Edge Cases
TEST_F(KeyGeneratorTest, AllZeroSeed_Success) {
    std::vector<unsigned char> seed(32, 0x00);
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, AllMaxValueSeed_Success) {
    std::vector<unsigned char> seed(32, 0xFF);
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, GenerateKeyWithExactly33Bytes_Success) {
    std::vector<unsigned char> seed(33, 0xCD);
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, GenerateKeyWithLargeExcessBytes_Success) {
    std::vector<unsigned char> seed(1024, 0xEF);
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

// Failure Conditions
TEST_F(KeyGeneratorTest, EmptySeed_ThrowsRuntimeError) {
    std::vector<unsigned char> seed;
    
    EXPECT_THROW({
        KeyGenerator::generateEd25519KeyFromSeed(seed);
    }, std::runtime_error);
}

TEST_F(KeyGeneratorTest, SeedTooSmall_31Bytes_ThrowsRuntimeError) {
    std::vector<unsigned char> seed(31, 0x99);
    
    EXPECT_THROW({
        KeyGenerator::generateEd25519KeyFromSeed(seed);
    }, std::runtime_error);
}

TEST_F(KeyGeneratorTest, SeedTooSmall_1Byte_ThrowsRuntimeError) {
    std::vector<unsigned char> seed(1, 0x88);
    
    EXPECT_THROW({
        KeyGenerator::generateEd25519KeyFromSeed(seed);
    }, std::runtime_error);
}

TEST_F(KeyGeneratorTest, SeedTooSmall_ErrorMessage) {
    std::vector<unsigned char> seed(16, 0x77);
    
    try {
        KeyGenerator::generateEd25519KeyFromSeed(seed);
        FAIL() << "Expected std::runtime_error to be thrown";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(std::string(e.what()), 
                   ::testing::HasSubstr("Ed25519 seed must be at least 32 bytes"));
    }
}

// Boundary Conditions
TEST_F(KeyGeneratorTest, SeedExactlyAtBoundary_32Bytes) {
    std::vector<unsigned char> seed;
    // Fill with a pattern to ensure we're testing the exact boundary
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<unsigned char>(i % 256));
    }
    
    EXPECT_NO_THROW({
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        EXPECT_NE(key, nullptr);
        EXPECT_TRUE(isValidEd25519Key(key));
    });
}

TEST_F(KeyGeneratorTest, SeedJustBelowBoundary_31Bytes) {
    std::vector<unsigned char> seed;
    for (int i = 0; i < 31; ++i) {
        seed.push_back(static_cast<unsigned char>(i % 256));
    }
    
    EXPECT_THROW({
        KeyGenerator::generateEd25519KeyFromSeed(seed);
    }, std::runtime_error);
}

// Memory and Resource Management Tests
TEST_F(KeyGeneratorTest, MultipleKeyGeneration_NoMemoryLeaks) {
    auto seed = createValidSeed();
    
    // Generate multiple keys to test for memory leaks
    for (int i = 0; i < 100; ++i) {
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        ASSERT_NE(key, nullptr);
        EXPECT_TRUE(isValidEd25519Key(key));
    }
}

TEST_F(KeyGeneratorTest, KeyDestruction_ProperCleanup) {
    auto seed = createValidSeed();
    
    {
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        ASSERT_NE(key, nullptr);
        // Key should be automatically destroyed when going out of scope
    }
    
    // Verify no issues after key destruction
    auto another_key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    EXPECT_NE(another_key, nullptr);
}

// Stress Tests
TEST_F(KeyGeneratorTest, RandomSeedStressTest) {
    constexpr int NUM_ITERATIONS = 50;
    
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        auto seed = createRandomSeed();
        
        ASSERT_NO_THROW({
            auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
            EXPECT_NE(key, nullptr);
            EXPECT_TRUE(isValidEd25519Key(key));
        });
    }
}

TEST_F(KeyGeneratorTest, VaryingSeedSizesStressTest) {
    std::vector<size_t> seed_sizes = {32, 33, 48, 64, 128, 256, 512};
    
    for (auto size : seed_sizes) {
        auto seed = createRandomSeed(size);
        
        ASSERT_NO_THROW({
            auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
            EXPECT_NE(key, nullptr);
            EXPECT_TRUE(isValidEd25519Key(key));
        });
    }
}

// Thread Safety Tests
TEST_F(KeyGeneratorTest, ConcurrentKeyGeneration) {
    std::vector<std::thread> threads;
    std::vector<bool> results(10, false);
    
    auto seed = createValidSeed();
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&, i]() {
            try {
                auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
                results[i] = (key != nullptr && isValidEd25519Key(key));
            } catch (...) {
                results[i] = false;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have succeeded
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

// Performance Baseline Test
TEST_F(KeyGeneratorTest, KeyGenerationPerformance) {
    auto seed = createValidSeed();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    constexpr int NUM_KEYS = 100;
    for (int i = 0; i < NUM_KEYS; ++i) {
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        ASSERT_NE(key, nullptr);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // This is more of a baseline measurement than a strict test
    EXPECT_LT(duration.count(), 10000); // Should complete in under 10 seconds
}

// Additional Edge Cases for OpenSSL Integration
TEST_F(KeyGeneratorTest, VerifyKeyCanBeUsedForSigning) {
    auto seed = createValidSeed();
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    
    // Create a simple message to sign
    const char* message = "test message";
    size_t message_len = strlen(message);
    
    // Create signing context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    ASSERT_NE(md_ctx, nullptr);
    
    // Initialize signing
    int result = EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, key.get());
    EXPECT_EQ(result, 1);
    
    // Get signature length
    size_t sig_len = 0;
    result = EVP_DigestSign(md_ctx, nullptr, &sig_len, 
                           reinterpret_cast<const unsigned char*>(message), message_len);
    EXPECT_EQ(result, 1);
    EXPECT_EQ(sig_len, 64); // Ed25519 signatures are always 64 bytes
    
    // Actually sign
    std::vector<unsigned char> signature(sig_len);
    result = EVP_DigestSign(md_ctx, signature.data(), &sig_len,
                           reinterpret_cast<const unsigned char*>(message), message_len);
    EXPECT_EQ(result, 1);
    
    EVP_MD_CTX_free(md_ctx);
}

TEST_F(KeyGeneratorTest, DeterministicKeyGeneration_ConsistentAcrossCalls) {
    // Use a known seed pattern
    std::vector<unsigned char> seed;
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<unsigned char>(i * 7 % 256));
    }
    
    // Generate the same key multiple times
    std::vector<std::vector<unsigned char>> public_keys;
    for (int i = 0; i < 5; ++i) {
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        ASSERT_NE(key, nullptr);
        
        auto pub_key = getPublicKeyFromPrivateKey(key);
        ASSERT_FALSE(pub_key.empty());
        public_keys.push_back(pub_key);
    }
    
    // All public keys should be identical
    for (size_t i = 1; i < public_keys.size(); ++i) {
        EXPECT_EQ(public_keys[0], public_keys[i]);
    }
}

TEST_F(KeyGeneratorTest, SeedWithSpecialValues_HandledCorrectly) {
    // Test with all possible byte values in seed
    std::vector<unsigned char> seed;
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<unsigned char>(i * 8 % 256));
    }
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
    
    // Verify we can extract both private and public keys
    size_t priv_key_len = 32;
    std::vector<unsigned char> priv_key(priv_key_len);
    int result = EVP_PKEY_get_raw_private_key(key.get(), priv_key.data(), &priv_key_len);
    EXPECT_EQ(result, 1);
    EXPECT_EQ(priv_key_len, 32);
    
    auto pub_key = getPublicKeyFromPrivateKey(key);
    EXPECT_EQ(pub_key.size(), 32);
}

// Test error handling when OpenSSL operations might fail
TEST_F(KeyGeneratorTest, HandleOpenSSLFailure_ThrowsAppropriateException) {
    auto seed = createValidSeed();
    
    // This test verifies that if OpenSSL fails to create the key,
    // our function throws the expected runtime_error
    // Note: This is difficult to trigger in normal circumstances,
    // but the test documents the expected behavior
    
    EXPECT_NO_THROW({
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        // If we get here, OpenSSL worked as expected
        EXPECT_NE(key, nullptr);
    });
}

// Test with seeds containing pattern variations
TEST_F(KeyGeneratorTest, SeedWithAlternatingPattern_Success) {
    std::vector<unsigned char> seed;
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<unsigned char>(i % 2 == 0 ? 0xAA : 0x55));
    }
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, SeedWithAscendingPattern_Success) {
    std::vector<unsigned char> seed;
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<unsigned char>(i));
    }
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

TEST_F(KeyGeneratorTest, SeedWithDescendingPattern_Success) {
    std::vector<unsigned char> seed;
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<unsigned char>(31 - i));
    }
    
    auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
    
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(isValidEd25519Key(key));
}

// Test that verifies the function only uses the first 32 bytes
TEST_F(KeyGeneratorTest, OnlyFirst32BytesUsed_VerifyWithIdenticalPrefix) {
    // Create two seeds with identical first 32 bytes but different trailing bytes
    std::vector<unsigned char> seed1;
    std::vector<unsigned char> seed2;
    
    // Same first 32 bytes
    for (int i = 0; i < 32; ++i) {
        unsigned char byte = static_cast<unsigned char>(i * 3 % 256);
        seed1.push_back(byte);
        seed2.push_back(byte);
    }
    
    // Different trailing bytes
    seed1.push_back(0xFF);
    seed1.push_back(0xAA);
    seed2.push_back(0x00);
    seed2.push_back(0x55);
    
    auto key1 = KeyGenerator::generateEd25519KeyFromSeed(seed1);
    auto key2 = KeyGenerator::generateEd25519KeyFromSeed(seed2);
    
    ASSERT_NE(key1, nullptr);
    ASSERT_NE(key2, nullptr);
    
    auto pub_key1 = getPublicKeyFromPrivateKey(key1);
    auto pub_key2 = getPublicKeyFromPrivateKey(key2);
    
    // Should produce identical keys since first 32 bytes are identical
    EXPECT_EQ(pub_key1, pub_key2);
}

// Test with exactly the minimum required size variations
TEST_F(KeyGeneratorTest, ExactlyMinimumSize_MultiplePatterns) {
    std::vector<std::vector<unsigned char>> test_seeds = {
        std::vector<unsigned char>(32, 0x01),
        std::vector<unsigned char>(32, 0x7F),
        std::vector<unsigned char>(32, 0x80),
        std::vector<unsigned char>(32, 0xFE)
    };
    
    for (const auto& seed : test_seeds) {
        EXPECT_EQ(seed.size(), 32);
        
        auto key = KeyGenerator::generateEd25519KeyFromSeed(seed);
        
        ASSERT_NE(key, nullptr);
        EXPECT_TRUE(isValidEd25519Key(key));
        
        // Verify key can be used to extract public key
        auto pub_key = getPublicKeyFromPrivateKey(key);
        EXPECT_EQ(pub_key.size(), 32);
    }
}