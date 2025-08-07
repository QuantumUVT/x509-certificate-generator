#include "../command_line_parser.h"
#include "../certificate_config.h"
#include <gtest/gtest.h>
#include <sstream>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>

// Helper function to convert vector of strings to char**
class ArgvHelper {
public:
    ArgvHelper(const std::vector<std::string>& args) {
        argc = args.size();
        argv = new char*[argc];
        for (size_t i = 0; i < args.size(); ++i) {
            argv[i] = new char[args[i].length() + 1];
            std::strcpy(argv[i], args[i].c_str());
        }
    }
    
    ~ArgvHelper() {
        for (int i = 0; i < argc; ++i) {
            delete[] argv[i];
        }
        delete[] argv;
    }
    
    int argc;
    char** argv;
};

class CommandLineParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = CertificateConfig();
        // Reset optind for getopt_long between tests
        optind = 1;
    }
    
    void TearDown() override {
        optind = 1;
    }
    
    CertificateConfig config;
    CommandLineParser parser;
};

// Test basic key argument parsing
TEST_F(CommandLineParserTest, ParsesSingleKeyArgument) {
    ArgvHelper helper({"program", "--key", "testkey.pem"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1); // Continue processing
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "testkey.pem");
}

// Test multiple key arguments
TEST_F(CommandLineParserTest, ParsesMultipleKeyArguments) {
    ArgvHelper helper({"program", "--key", "key1.pem", "--key", "key2.pem", "--key", "key3.pem"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 3);
    EXPECT_EQ(config.keys[0], "key1.pem");
    EXPECT_EQ(config.keys[1], "key2.pem");
    EXPECT_EQ(config.keys[2], "key3.pem");
}

// Test short option for key
TEST_F(CommandLineParserTest, ParsesShortKeyOption) {
    ArgvHelper helper({"program", "-k", "shortkey.pem"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "shortkey.pem");
}

// Test prefix argument parsing
TEST_F(CommandLineParserTest, ParsesPrefixArgument) {
    ArgvHelper helper({"program", "--key", "test.pem", "--prefix", "mycert"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.prefix, "mycert");
}

// Test prefix argument with short option
TEST_F(CommandLineParserTest, ParsesShortPrefixOption) {
    ArgvHelper helper({"program", "--key", "test.pem", "-p", "shortprefix"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.prefix, "shortprefix");
}

// Test days argument parsing with valid value
TEST_F(CommandLineParserTest, ParsesValidDaysArgument) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "365"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.days, 365);
}

// Test days argument with short option
TEST_F(CommandLineParserTest, ParsesShortDaysOption) {
    ArgvHelper helper({"program", "--key", "test.pem", "-d", "730"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.days, 730);
}

// Test days argument with zero value (invalid)
TEST_F(CommandLineParserTest, RejectsZeroDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "0"});
    
    // Redirect stderr to capture error message
    std::stringstream buffer;
    std::streambuf* old_cerr = std::cerr.rdbuf(buffer.rdbuf());
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    std::cerr.rdbuf(old_cerr);
    
    EXPECT_EQ(result, 1);
    EXPECT_NE(buffer.str().find("Invalid days value: 0"), std::string::npos);
}

// Test days argument with negative value (invalid)
TEST_F(CommandLineParserTest, RejectsNegativeDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "-10"});
    
    std::stringstream buffer;
    std::streambuf* old_cerr = std::cerr.rdbuf(buffer.rdbuf());
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    std::cerr.rdbuf(old_cerr);
    
    EXPECT_EQ(result, 1);
    EXPECT_NE(buffer.str().find("Invalid days value: -10"), std::string::npos);
}

// Test days argument with non-numeric value
TEST_F(CommandLineParserTest, RejectsNonNumericDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "abc"});
    
    std::stringstream buffer;
    std::streambuf* old_cerr = std::cerr.rdbuf(buffer.rdbuf());
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    std::cerr.rdbuf(old_cerr);
    
    EXPECT_EQ(result, 1);
    EXPECT_NE(buffer.str().find("Invalid days value: abc"), std::string::npos);
}

// Test all certificate subject fields with long options
TEST_F(CommandLineParserTest, ParsesAllCertificateFields) {
    ArgvHelper helper({"program", "--key", "test.pem", 
                      "--C", "US", "--ST", "California", "--L", "San Francisco",
                      "--O", "MyOrg", "--OU", "Engineering", "--CN", "example.com"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.country, "US");
    EXPECT_EQ(config.state, "California");
    EXPECT_EQ(config.locality, "San Francisco");
    EXPECT_EQ(config.organization, "MyOrg");
    EXPECT_EQ(config.organizational_unit, "Engineering");
    EXPECT_EQ(config.common_name, "example.com");
}

// Test short options for certificate fields
TEST_F(CommandLineParserTest, ParsesShortCertificateOptions) {
    ArgvHelper helper({"program", "-k", "test.pem", 
                      "-c", "CA", "-s", "Ontario", "-l", "Toronto",
                      "-o", "TestCorp", "-u", "IT", "-n", "test.example.com"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.country, "CA");
    EXPECT_EQ(config.state, "Ontario");
    EXPECT_EQ(config.locality, "Toronto");
    EXPECT_EQ(config.organization, "TestCorp");
    EXPECT_EQ(config.organizational_unit, "IT");
    EXPECT_EQ(config.common_name, "test.example.com");
}

// Test help option returns 0
TEST_F(CommandLineParserTest, HelpOptionReturnsZero) {
    ArgvHelper helper({"program", "--help"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, 0);
}

// Test short help option
TEST_F(CommandLineParserTest, ShortHelpOptionReturnsZero) {
    ArgvHelper helper({"program", "-h"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, 0);
}

// Test missing key argument returns error
TEST_F(CommandLineParserTest, MissingKeyArgumentReturnsError) {
    ArgvHelper helper({"program", "--prefix", "test"});
    
    std::stringstream buffer;
    std::streambuf* old_cerr = std::cerr.rdbuf(buffer.rdbuf());
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    std::cerr.rdbuf(old_cerr);
    
    EXPECT_EQ(result, 1);
    EXPECT_NE(buffer.str().find("At least one --key argument is required"), std::string::npos);
}

// Test invalid option returns error
TEST_F(CommandLineParserTest, InvalidOptionReturnsError) {
    ArgvHelper helper({"program", "--key", "test.pem", "--invalid"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, 1);
}

// Test mixed long and short options
TEST_F(CommandLineParserTest, MixedLongAndShortOptions) {
    ArgvHelper helper({"program", "-k", "key1.pem", "--key", "key2.pem",
                      "--prefix", "mixed", "-d", "730"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 2);
    EXPECT_EQ(config.keys[0], "key1.pem");
    EXPECT_EQ(config.keys[1], "key2.pem");
    EXPECT_EQ(config.prefix, "mixed");
    EXPECT_EQ(config.days, 730);
}

// Test empty string arguments
TEST_F(CommandLineParserTest, HandlesEmptyStringArguments) {
    ArgvHelper helper({"program", "--key", "", "--prefix", ""});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "");
    EXPECT_EQ(config.prefix, "");
}

// Test very long argument values
TEST_F(CommandLineParserTest, HandlesLongArgumentValues) {
    std::string long_key(1000, 'a');
    std::string long_prefix(500, 'b');
    ArgvHelper helper({"program", "--key", long_key, "--prefix", long_prefix});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], long_key);
    EXPECT_EQ(config.prefix, long_prefix);
}

// Test special characters in arguments
TEST_F(CommandLineParserTest, HandlesSpecialCharactersInArguments) {
    ArgvHelper helper({"program", "--key", "key@#$%.pem", "--CN", "test!@#$%^&*().com"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "key@#$%.pem");
    EXPECT_EQ(config.common_name, "test!@#$%^&*().com");
}

// Test Unicode characters in arguments
TEST_F(CommandLineParserTest, HandlesUnicodeCharactersInArguments) {
    ArgvHelper helper({"program", "--key", "clé.pem", "--O", "Organizaçãö"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "clé.pem");
    EXPECT_EQ(config.organization, "Organizaçãö");
}

// Test maximum integer value for days
TEST_F(CommandLineParserTest, HandlesMaximumDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "2147483647"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.days, 2147483647);
}

// Test large valid days value
TEST_F(CommandLineParserTest, HandlesLargeDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "999999"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.days, 999999);
}

// Test that default values are preserved when not specified
TEST_F(CommandLineParserTest, PreservesDefaultValues) {
    ArgvHelper helper({"program", "--key", "test.pem"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.prefix, "qkd_ed25519"); // Default value
    EXPECT_EQ(config.days, 365); // Default value
    EXPECT_EQ(config.country, ""); // Empty default
    EXPECT_EQ(config.state, ""); // Empty default
    EXPECT_EQ(config.locality, ""); // Empty default
    EXPECT_EQ(config.organization, ""); // Empty default
    EXPECT_EQ(config.organizational_unit, ""); // Empty default
    EXPECT_EQ(config.common_name, ""); // Empty default
}

// Test comprehensive argument combination
TEST_F(CommandLineParserTest, ComprehensiveArgumentCombination) {
    ArgvHelper helper({"program", 
                      "--key", "primary.pem", 
                      "--key", "backup.pem",
                      "--prefix", "comprehensive",
                      "--days", "1825",
                      "--C", "US",
                      "--ST", "New York",
                      "--L", "New York City",
                      "--O", "Test Organization Inc.",
                      "--OU", "Quality Assurance",
                      "--CN", "comprehensive.test.example.com"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 2);
    EXPECT_EQ(config.keys[0], "primary.pem");
    EXPECT_EQ(config.keys[1], "backup.pem");
    EXPECT_EQ(config.prefix, "comprehensive");
    EXPECT_EQ(config.days, 1825);
    EXPECT_EQ(config.country, "US");
    EXPECT_EQ(config.state, "New York");
    EXPECT_EQ(config.locality, "New York City");
    EXPECT_EQ(config.organization, "Test Organization Inc.");
    EXPECT_EQ(config.organizational_unit, "Quality Assurance");
    EXPECT_EQ(config.common_name, "comprehensive.test.example.com");
}

// Test whitespace-only arguments
TEST_F(CommandLineParserTest, HandlesWhitespaceOnlyArguments) {
    ArgvHelper helper({"program", "--key", "   ", "--prefix", "\t\n"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "   ");
    EXPECT_EQ(config.prefix, "\t\n");
}

// Test edge cases for days parsing
TEST_F(CommandLineParserTest, HandlesEdgeCasesForDays) {
    // Test days with leading zeros
    ArgvHelper helper1({"program", "--key", "test.pem", "--days", "0365"});
    int result1 = parser.parseArguments(helper1.argc, helper1.argv, config);
    EXPECT_EQ(result1, -1);
    EXPECT_EQ(config.days, 365);
}

// Test days with leading whitespace in value
TEST_F(CommandLineParserTest, HandlesWhitespaceInDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", " 100 "});
    
    std::stringstream buffer;
    std::streambuf* old_cerr = std::cerr.rdbuf(buffer.rdbuf());
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    std::cerr.rdbuf(old_cerr);
    
    // atoi() will parse " 100 " as 100, so this should succeed
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.days, 100);
}

// Test argument parsing with spaces in values
TEST_F(CommandLineParserTest, HandlesSpacesInValues) {
    ArgvHelper helper({"program", "--key", "my key file.pem", "--O", "My Organization Name"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 1);
    EXPECT_EQ(config.keys[0], "my key file.pem");
    EXPECT_EQ(config.organization, "My Organization Name");
}

// Test boundary conditions for string lengths
TEST_F(CommandLineParserTest, HandlesBoundaryStringLengths) {
    // Single character arguments
    ArgvHelper helper1({"program", "--key", "k", "--C", "A"});
    int result1 = parser.parseArguments(helper1.argc, helper1.argv, config);
    EXPECT_EQ(result1, -1);
    EXPECT_EQ(config.keys[0], "k");
    EXPECT_EQ(config.country, "A");
}

// Test option order independence
TEST_F(CommandLineParserTest, HandlesOptionOrderIndependence) {
    // Test with options in different order
    ArgvHelper helper1({"program", "--days", "100", "--key", "test.pem", "--prefix", "first"});
    int result1 = parser.parseArguments(helper1.argc, helper1.argv, config);
    EXPECT_EQ(result1, -1);
    EXPECT_EQ(config.days, 100);
    EXPECT_EQ(config.keys[0], "test.pem");
    EXPECT_EQ(config.prefix, "first");
    
    // Reset and test different order
    config = CertificateConfig();
    optind = 1;
    
    ArgvHelper helper2({"program", "--prefix", "second", "--days", "200", "--key", "test2.pem"});
    int result2 = parser.parseArguments(helper2.argc, helper2.argv, config);
    EXPECT_EQ(result2, -1);
    EXPECT_EQ(config.prefix, "second");
    EXPECT_EQ(config.days, 200);
    EXPECT_EQ(config.keys[0], "test2.pem");
}

// Test that the function correctly handles the case when no arguments are passed
TEST_F(CommandLineParserTest, HandlesNoArgumentsCase) {
    ArgvHelper helper({"program"});
    
    std::stringstream buffer;
    std::streambuf* old_cerr = std::cerr.rdbuf(buffer.rdbuf());
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    std::cerr.rdbuf(old_cerr);
    
    EXPECT_EQ(result, 1); // Should return error
    EXPECT_NE(buffer.str().find("At least one --key argument is required"), std::string::npos);
}

// Test days value of exactly 1
TEST_F(CommandLineParserTest, HandlesMinimumValidDaysValue) {
    ArgvHelper helper({"program", "--key", "test.pem", "--days", "1"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.days, 1);
}

// Test multiple keys with other options interspersed
TEST_F(CommandLineParserTest, HandlesInterspersedKeysAndOptions) {
    ArgvHelper helper({"program", "--key", "key1.pem", "--prefix", "test", 
                      "--key", "key2.pem", "--days", "500", "--key", "key3.pem"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    ASSERT_EQ(config.keys.size(), 3);
    EXPECT_EQ(config.keys[0], "key1.pem");
    EXPECT_EQ(config.keys[1], "key2.pem");
    EXPECT_EQ(config.keys[2], "key3.pem");
    EXPECT_EQ(config.prefix, "test");
    EXPECT_EQ(config.days, 500);
}

// Test unknown short option
TEST_F(CommandLineParserTest, HandlesUnknownShortOption) {
    ArgvHelper helper({"program", "--key", "test.pem", "-x"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, 1); // Should return error for unknown option
}

// Test option requiring argument but not provided
TEST_F(CommandLineParserTest, HandlesMissingRequiredArgument) {
    ArgvHelper helper({"program", "--key"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, 1); // Should return error
}

// Performance test with many keys
TEST_F(CommandLineParserTest, HandlesVeryManyKeys) {
    std::vector<std::string> args = {"program"};
    const int num_keys = 100; // Reduced for practical testing
    
    for (int i = 0; i < num_keys; ++i) {
        args.push_back("--key");
        args.push_back("key" + std::to_string(i) + ".pem");
    }
    
    ArgvHelper helper(args);
    
    auto start = std::chrono::high_resolution_clock::now();
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.keys.size(), num_keys);
    // Should complete within reasonable time
    EXPECT_LT(duration.count(), 1000);
    
    // Verify some keys are parsed correctly
    EXPECT_EQ(config.keys[0], "key0.pem");
    EXPECT_EQ(config.keys[num_keys-1], "key" + std::to_string(num_keys-1) + ".pem");
}

// Test memory management with multiple parse calls
TEST_F(CommandLineParserTest, HandlesMultipleParseCalls) {
    for (int i = 0; i < 10; ++i) {
        config = CertificateConfig();
        optind = 1;
        
        ArgvHelper helper({"program", "--key", "test" + std::to_string(i) + ".pem"});
        int result = parser.parseArguments(helper.argc, helper.argv, config);
        
        EXPECT_EQ(result, -1);
        EXPECT_EQ(config.keys.size(), 1);
        EXPECT_EQ(config.keys[0], "test" + std::to_string(i) + ".pem");
    }
}

// Test that overwrites work correctly for single-value options
TEST_F(CommandLineParserTest, HandlesOptionOverwrites) {
    ArgvHelper helper({"program", "--key", "test.pem", 
                      "--prefix", "first", "--prefix", "second",
                      "--days", "100", "--days", "200"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    EXPECT_EQ(config.prefix, "second"); // Should be overwritten
    EXPECT_EQ(config.days, 200); // Should be overwritten
}

// Test parsing with very large number of certificate fields
TEST_F(CommandLineParserTest, HandlesAllFieldsWithOverwrites) {
    ArgvHelper helper({"program", "--key", "test.pem",
                      "--C", "US", "--C", "CA", // Test overwrite
                      "--ST", "State1", "--ST", "State2",
                      "--L", "City1", "--L", "City2",
                      "--O", "Org1", "--O", "Org2",
                      "--OU", "Unit1", "--OU", "Unit2", 
                      "--CN", "name1.com", "--CN", "name2.com"});
    
    int result = parser.parseArguments(helper.argc, helper.argv, config);
    
    EXPECT_EQ(result, -1);
    // All should have the last (overwritten) value
    EXPECT_EQ(config.country, "CA");
    EXPECT_EQ(config.state, "State2");
    EXPECT_EQ(config.locality, "City2");
    EXPECT_EQ(config.organization, "Org2");
    EXPECT_EQ(config.organizational_unit, "Unit2");
    EXPECT_EQ(config.common_name, "name2.com");
}
