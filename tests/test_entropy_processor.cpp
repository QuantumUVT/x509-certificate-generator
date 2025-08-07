#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "entropy_processor.h"
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <random>

// Test fixture for EntropyProcessor tests
class EntropyProcessorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize common test data
        valid_data = {0x01, 0x02, 0x03, 0x04, 0x05};
        empty_data = {};
        min_entropy_data = std::vector<unsigned char>(16, 0xAB); // Exactly 16 bytes
        large_entropy_data = std::vector<unsigned char>(64, 0xCD); // 64 bytes
        insufficient_entropy = std::vector<unsigned char>(15, 0xEF); // Only 15 bytes
        
        // Create a known test vector for deterministic testing
        known_input = {0x61, 0x62, 0x63}; // "abc" in ASCII
        // Expected SHA256 hash of "abc"
        expected_abc_hash = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
    }

    std::vector<unsigned char> valid_data;
    std::vector<unsigned char> empty_data;
    std::vector<unsigned char> min_entropy_data;
    std::vector<unsigned char> large_entropy_data;
    std::vector<unsigned char> insufficient_entropy;
    std::vector<unsigned char> known_input;
    std::vector<unsigned char> expected_abc_hash;
    EntropyProcessor processor;
};

// Tests for sha256Hash function

TEST_F(EntropyProcessorTest, Sha256Hash_ValidData_ReturnsCorrectHash) {
    auto result = processor.sha256Hash(known_input);
    
    EXPECT_EQ(result.size(), 32); // SHA256 produces 32 bytes
    EXPECT_EQ(result, expected_abc_hash);
}

TEST_F(EntropyProcessorTest, Sha256Hash_EmptyData_ThrowsException) {
    EXPECT_THROW(processor.sha256Hash(empty_data), std::runtime_error);
    
    try {
        processor.sha256Hash(empty_data);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "Cannot hash empty data");
    }
}

TEST_F(EntropyProcessorTest, Sha256Hash_SingleByte_ReturnsValidHash) {
    std::vector<unsigned char> single_byte = {0xFF};
    auto result = processor.sha256Hash(single_byte);
    
    EXPECT_EQ(result.size(), 32);
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char b) { return b == 0; }));
}

TEST_F(EntropyProcessorTest, Sha256Hash_LargeData_ReturnsValidHash) {
    std::vector<unsigned char> large_data(10000, 0x42);
    auto result = processor.sha256Hash(large_data);
    
    EXPECT_EQ(result.size(), 32);
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char b) { return b == 0; }));
}

TEST_F(EntropyProcessorTest, Sha256Hash_DifferentInputs_ProduceDifferentHashes) {
    std::vector<unsigned char> input1 = {0x01, 0x02, 0x03};
    std::vector<unsigned char> input2 = {0x01, 0x02, 0x04}; // Last byte different
    
    auto hash1 = processor.sha256Hash(input1);
    auto hash2 = processor.sha256Hash(input2);
    
    EXPECT_NE(hash1, hash2);
}

TEST_F(EntropyProcessorTest, Sha256Hash_SameInputs_ProduceSameHashes) {
    auto hash1 = processor.sha256Hash(valid_data);
    auto hash2 = processor.sha256Hash(valid_data);
    
    EXPECT_EQ(hash1, hash2);
}

TEST_F(EntropyProcessorTest, Sha256Hash_MaxSizeData_HandlesGracefully) {
    // Test with a reasonably large buffer to ensure no overflow issues
    std::vector<unsigned char> max_data(65536, 0xAA); // 64KB
    auto result = processor.sha256Hash(max_data);
    
    EXPECT_EQ(result.size(), 32);
}

TEST_F(EntropyProcessorTest, Sha256Hash_AllZeros_ReturnsValidHash) {
    std::vector<unsigned char> zeros(32, 0x00);
    auto result = processor.sha256Hash(zeros);
    
    EXPECT_EQ(result.size(), 32);
    // Hash of all zeros should not be all zeros
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char b) { return b == 0; }));
}

TEST_F(EntropyProcessorTest, Sha256Hash_AllOnes_ReturnsValidHash) {
    std::vector<unsigned char> ones(32, 0xFF);
    auto result = processor.sha256Hash(ones);
    
    EXPECT_EQ(result.size(), 32);
    // Hash should be deterministic
    auto result2 = processor.sha256Hash(ones);
    EXPECT_EQ(result, result2);
}

// Tests for deriveEd25519Seed function

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_MinimumEntropy_ReturnsValidSeed) {
    auto result = processor.deriveEd25519Seed(min_entropy_data);
    
    EXPECT_EQ(result.size(), 32); // Ed25519 seed is 32 bytes
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char b) { return b == 0; }));
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_LargeEntropy_ReturnsValidSeed) {
    auto result = processor.deriveEd25519Seed(large_entropy_data);
    
    EXPECT_EQ(result.size(), 32);
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char b) { return b == 0; }));
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_InsufficientEntropy_ThrowsException) {
    EXPECT_THROW(processor.deriveEd25519Seed(insufficient_entropy), std::runtime_error);
    
    try {
        processor.deriveEd25519Seed(insufficient_entropy);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "Insufficient entropy: need at least 16 bytes from QKD keys");
    }
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_EmptyEntropy_ThrowsException) {
    EXPECT_THROW(processor.deriveEd25519Seed(empty_data), std::runtime_error);
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_Exactly16Bytes_ReturnsValidSeed) {
    std::vector<unsigned char> exactly_16_bytes(16, 0x88);
    auto result = processor.deriveEd25519Seed(exactly_16_bytes);
    
    EXPECT_EQ(result.size(), 32);
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_DeterministicOutput_SameInputSameOutput) {
    auto result1 = processor.deriveEd25519Seed(min_entropy_data);
    auto result2 = processor.deriveEd25519Seed(min_entropy_data);
    
    EXPECT_EQ(result1, result2);
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_DifferentInputs_DifferentOutputs) {
    std::vector<unsigned char> entropy1(16, 0x11);
    std::vector<unsigned char> entropy2(16, 0x22);
    
    auto seed1 = processor.deriveEd25519Seed(entropy1);
    auto seed2 = processor.deriveEd25519Seed(entropy2);
    
    EXPECT_NE(seed1, seed2);
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_UsesInternalSha256Hash) {
    // Test that deriveEd25519Seed produces the same result as calling sha256Hash directly
    auto direct_hash = processor.sha256Hash(min_entropy_data);
    auto derived_seed = processor.deriveEd25519Seed(min_entropy_data);
    
    EXPECT_EQ(direct_hash, derived_seed);
}

TEST_F(EntropyProcessorTest, DeriveEd25519Seed_VariousEntropyLengths_AllValidSeeds) {
    std::vector<size_t> test_sizes = {16, 17, 32, 64, 128, 256};
    
    for (size_t size : test_sizes) {
        std::vector<unsigned char> entropy(size, static_cast<unsigned char>(size % 256));
        auto result = processor.deriveEd25519Seed(entropy);
        
        EXPECT_EQ(result.size(), 32) << "Failed for entropy size: " << size;
        EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char b) { return b == 0; }))
            << "All-zero result for entropy size: " << size;
    }
}

// Edge case tests

TEST_F(EntropyProcessorTest, EdgeCase_15BytesEntropy_ThrowsException) {
    std::vector<unsigned char> edge_case(15, 0x99);
    EXPECT_THROW(processor.deriveEd25519Seed(edge_case), std::runtime_error);
}

TEST_F(EntropyProcessorTest, EdgeCase_RandomEntropyValues_ProducesValidResults) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (int i = 0; i < 10; ++i) {
        std::vector<unsigned char> random_entropy(32);
        std::generate(random_entropy.begin(), random_entropy.end(), [&]() { return dis(gen); });
        
        auto result = processor.deriveEd25519Seed(random_entropy);
        EXPECT_EQ(result.size(), 32);
    }
}

TEST_F(EntropyProcessorTest, EdgeCase_VeryLargeEntropy_HandlesGracefully) {
    std::vector<unsigned char> very_large_entropy(100000, 0x77); // 100KB
    auto result = processor.deriveEd25519Seed(very_large_entropy);
    
    EXPECT_EQ(result.size(), 32);
}

// Performance and boundary tests

TEST_F(EntropyProcessorTest, Performance_MultipleDerivations_Consistent) {
    const int num_iterations = 100;
    std::vector<unsigned char> test_entropy(64, 0x55);
    
    auto first_result = processor.deriveEd25519Seed(test_entropy);
    
    for (int i = 0; i < num_iterations; ++i) {
        auto result = processor.deriveEd25519Seed(test_entropy);
        EXPECT_EQ(result, first_result) << "Inconsistent result at iteration " << i;
    }
}

TEST_F(EntropyProcessorTest, Boundary_ExactlyMinimumSize_Success) {
    std::vector<unsigned char> boundary_entropy(16, 0xBB);
    EXPECT_NO_THROW(processor.deriveEd25519Seed(boundary_entropy));
    
    auto result = processor.deriveEd25519Seed(boundary_entropy);
    EXPECT_EQ(result.size(), 32);
}

TEST_F(EntropyProcessorTest, Boundary_OneBelowMinimum_Failure) {
    std::vector<unsigned char> below_minimum(15, 0xCC);
    EXPECT_THROW(processor.deriveEd25519Seed(below_minimum), std::runtime_error);
}

// Integration test combining both functions
TEST_F(EntropyProcessorTest, Integration_Sha256AndDerive_WorkTogether) {
    std::vector<unsigned char> source_data(32, 0x44);
    
    // First hash the data
    auto hashed = processor.sha256Hash(source_data);
    EXPECT_EQ(hashed.size(), 32);
    
    // Then use the hash as entropy (it's 32 bytes, so > 16 minimum)
    auto seed = processor.deriveEd25519Seed(hashed);
    EXPECT_EQ(seed.size(), 32);
    
    // The seed should be the same as hashing the hash again
    auto double_hash = processor.sha256Hash(hashed);
    EXPECT_EQ(seed, double_hash);
}