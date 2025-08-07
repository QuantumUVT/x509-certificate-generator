#include "../usage_printer.h"
#include <iostream>
#include <sstream>
#include <string>
#include <cassert>
#include <algorithm>

class TestOutputCapture {
private:
    std::ostringstream output_buffer;
    std::streambuf* original_cout_buffer;

public:
    void startCapture() {
        original_cout_buffer = std::cout.rdbuf();
        std::cout.rdbuf(output_buffer.rdbuf());
    }

    void stopCapture() {
        std::cout.rdbuf(original_cout_buffer);
    }

    std::string getCapturedOutput() {
        return output_buffer.str();
    }

    void clearOutput() {
        output_buffer.str("");
        output_buffer.clear();
    }
};

// Simple assertion macros
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cerr << "ASSERTION FAILED: " << message << " at line " << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define TEST_ASSERT_TRUE(condition) TEST_ASSERT((condition), #condition " should be true")
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition), #condition " should be false")
#define TEST_ASSERT_CONTAINS(str, substr) TEST_ASSERT((str).find(substr) != std::string::npos, "String should contain: " #substr)
#define TEST_ASSERT_NOT_CONTAINS(str, substr) TEST_ASSERT((str).find(substr) == std::string::npos, "String should not contain: " #substr)
#define TEST_ASSERT_GE(a, b) TEST_ASSERT((a) >= (b), #a " should be >= " #b)
#define TEST_ASSERT_EQ(a, b) TEST_ASSERT((a) == (b), #a " should equal " #b)

// Test function declarations
bool test_printUsage_standardProgramName();
bool test_printUsage_containsAllOptions();
bool test_printUsage_containsOptionDescriptions();
bool test_printUsage_emptyProgramName();
bool test_printUsage_nullProgramName();
bool test_printUsage_longProgramName();
bool test_printUsage_specialCharactersProgramName();
bool test_printUsage_properFormatting();
bool test_printUsage_multipleCalls();
bool test_printUsage_outputCompleteness();
bool test_printUsage_certificateTerminology();
bool test_printUsage_staticMethodBehavior();
bool test_printUsage_x509FieldsPresent();
bool test_printUsage_defaultValueAccuracy();
bool test_printUsage_helpMessageStructure();

// Test basic functionality with standard program name
bool test_printUsage_standardProgramName() {
    TestOutputCapture capture;
    const char* program_name = "qkd_cert_gen";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify the usage line contains the program name
    TEST_ASSERT_CONTAINS(output, "Usage: qkd_cert_gen [OPTIONS]");
    
    // Verify main description is present
    TEST_ASSERT_CONTAINS(output, "Generate Ed25519 X.509 cert from QKD keys");
    
    // Verify Options section header
    TEST_ASSERT_CONTAINS(output, "Options:");
    
    return true;
}

// Test all command line options are documented
bool test_printUsage_containsAllOptions() {
    TestOutputCapture capture;
    const char* program_name = "test_program";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify all expected options are present
    TEST_ASSERT_CONTAINS(output, "--key KEY");
    TEST_ASSERT_CONTAINS(output, "--prefix PREFIX");
    TEST_ASSERT_CONTAINS(output, "--days DAYS");
    TEST_ASSERT_CONTAINS(output, "--C COUNTRY");
    TEST_ASSERT_CONTAINS(output, "--ST STATE");
    TEST_ASSERT_CONTAINS(output, "--L LOCALITY");
    TEST_ASSERT_CONTAINS(output, "--O ORG");
    TEST_ASSERT_CONTAINS(output, "--OU ORG_UNIT");
    TEST_ASSERT_CONTAINS(output, "--CN COMMON_NAME");
    TEST_ASSERT_CONTAINS(output, "--help");
    
    return true;
}

// Test option descriptions are present
bool test_printUsage_containsOptionDescriptions() {
    TestOutputCapture capture;
    const char* program_name = "test_program";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify option descriptions
    TEST_ASSERT_CONTAINS(output, "Base64-encoded QKD key");
    TEST_ASSERT_CONTAINS(output, "can be used multiple times");
    TEST_ASSERT_CONTAINS(output, "Filename prefix for cert and key");
    TEST_ASSERT_CONTAINS(output, "default: qkd_ed25519");
    TEST_ASSERT_CONTAINS(output, "Certificate validity in days");
    TEST_ASSERT_CONTAINS(output, "default: 365");
    TEST_ASSERT_CONTAINS(output, "Country Name");
    TEST_ASSERT_CONTAINS(output, "e.g., RO");
    TEST_ASSERT_CONTAINS(output, "State or Province Name");
    TEST_ASSERT_CONTAINS(output, "Locality Name");
    TEST_ASSERT_CONTAINS(output, "Organization Name");
    TEST_ASSERT_CONTAINS(output, "Organizational Unit Name");
    TEST_ASSERT_CONTAINS(output, "Common Name");
    TEST_ASSERT_CONTAINS(output, "Show this help message");
    
    return true;
}

// Test with empty program name
bool test_printUsage_emptyProgramName() {
    TestOutputCapture capture;
    const char* program_name = "";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Should still work with empty program name
    TEST_ASSERT_CONTAINS(output, "Usage:  [OPTIONS]");
    TEST_ASSERT_CONTAINS(output, "Generate Ed25519 X.509 cert from QKD keys");
    
    return true;
}

// Test with null program name (edge case)
bool test_printUsage_nullProgramName() {
    TestOutputCapture capture;
    
    // This test checks that the function handles null input gracefully
    // The behavior might be undefined, but we test that it doesn't crash
    capture.startCapture();
    try {
        UsagePrinter::printUsage(nullptr);
        capture.stopCapture();
        // If we reach here, the function handled null gracefully
        return true;
    } catch (...) {
        capture.stopCapture();
        // Function threw an exception with null input - this is acceptable behavior
        return true;
    }
}

// Test with very long program name
bool test_printUsage_longProgramName() {
    TestOutputCapture capture;
    const char* program_name = "very_long_program_name_that_exceeds_normal_length_expectations_for_testing_purposes";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify the long program name is included
    TEST_ASSERT_CONTAINS(output, program_name);
    TEST_ASSERT_CONTAINS(output, "Generate Ed25519 X.509 cert from QKD keys");
    
    return true;
}

// Test with program name containing special characters
bool test_printUsage_specialCharactersProgramName() {
    TestOutputCapture capture;
    const char* program_name = "./program-name_with.special@chars";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify special characters are handled correctly
    TEST_ASSERT_CONTAINS(output, program_name);
    TEST_ASSERT_CONTAINS(output, "Usage: ./program-name_with.special@chars [OPTIONS]");
    
    return true;
}

// Test that output is properly formatted with newlines
bool test_printUsage_properFormatting() {
    TestOutputCapture capture;
    const char* program_name = "test_program";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Count newlines to ensure proper formatting
    int newline_count = std::count(output.begin(), output.end(), '\n');
    TEST_ASSERT_GE(newline_count, 10); // Should have multiple lines
    
    // Check for proper spacing after Options header
    TEST_ASSERT_CONTAINS(output, "Options:\n");
    
    // Check that options are properly indented
    TEST_ASSERT_CONTAINS(output, "  --key");
    TEST_ASSERT_CONTAINS(output, "  --help");
    
    return true;
}

// Test multiple calls don't interfere with each other
bool test_printUsage_multipleCalls() {
    TestOutputCapture capture;
    
    // First call
    capture.startCapture();
    UsagePrinter::printUsage("program1");
    capture.stopCapture();
    std::string first_output = capture.getCapturedOutput();
    capture.clearOutput();
    
    // Second call
    capture.startCapture();
    UsagePrinter::printUsage("program2");
    capture.stopCapture();
    std::string second_output = capture.getCapturedOutput();
    
    // Both should contain their respective program names
    TEST_ASSERT_CONTAINS(first_output, "program1");
    TEST_ASSERT_CONTAINS(second_output, "program2");
    
    // Both should contain the same structure
    TEST_ASSERT_CONTAINS(first_output, "Generate Ed25519 X.509 cert from QKD keys");
    TEST_ASSERT_CONTAINS(second_output, "Generate Ed25519 X.509 cert from QKD keys");
    
    return true;
}

// Test output consistency and completeness
bool test_printUsage_outputCompleteness() {
    TestOutputCapture capture;
    const char* program_name = "complete_test";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify all major sections are present
    TEST_ASSERT_CONTAINS(output, "Usage:");
    TEST_ASSERT_CONTAINS(output, "Generate Ed25519 X.509 cert from QKD keys");
    TEST_ASSERT_CONTAINS(output, "Options:");
    
    // Verify minimum expected length (should be substantial)
    TEST_ASSERT_GE(output.length(), 400); // Reasonable minimum for complete help text
    
    // Verify output ends with newline for proper terminal display
    TEST_ASSERT_EQ(output.back(), '\n');
    
    return true;
}

// Test that output contains expected certificate-related terminology
bool test_printUsage_certificateTerminology() {
    TestOutputCapture capture;
    const char* program_name = "cert_test";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Check for certificate-specific terms
    TEST_ASSERT_CONTAINS(output, "Ed25519");
    TEST_ASSERT_CONTAINS(output, "X.509");
    TEST_ASSERT_CONTAINS(output, "QKD");
    TEST_ASSERT_CONTAINS(output, "cert");
    TEST_ASSERT_CONTAINS(output, "Certificate validity");
    TEST_ASSERT_CONTAINS(output, "Country Name");
    TEST_ASSERT_CONTAINS(output, "Common Name");
    
    return true;
}

// Test static method behavior
bool test_printUsage_staticMethodBehavior() {
    TestOutputCapture capture;
    
    // Test that static method can be called without creating an instance
    capture.startCapture();
    UsagePrinter::printUsage("static_test");
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    TEST_ASSERT_CONTAINS(output, "static_test");
    TEST_ASSERT_CONTAINS(output, "Usage:");
    TEST_ASSERT_CONTAINS(output, "Options:");
    
    return true;
}

// Test that all X.509 certificate fields are documented
bool test_printUsage_x509FieldsPresent() {
    TestOutputCapture capture;
    const char* program_name = "x509_test";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify all standard X.509 distinguished name fields are present
    TEST_ASSERT_CONTAINS(output, "--C");   // Country
    TEST_ASSERT_CONTAINS(output, "--ST");  // State/Province
    TEST_ASSERT_CONTAINS(output, "--L");   // Locality
    TEST_ASSERT_CONTAINS(output, "--O");   // Organization
    TEST_ASSERT_CONTAINS(output, "--OU");  // Organizational Unit
    TEST_ASSERT_CONTAINS(output, "--CN");  // Common Name
    
    // Verify field descriptions use proper X.509 terminology
    TEST_ASSERT_CONTAINS(output, "Country Name");
    TEST_ASSERT_CONTAINS(output, "State or Province Name");
    TEST_ASSERT_CONTAINS(output, "Locality Name");
    TEST_ASSERT_CONTAINS(output, "Organization Name");
    TEST_ASSERT_CONTAINS(output, "Organizational Unit Name");
    TEST_ASSERT_CONTAINS(output, "Common Name");
    
    return true;
}

// Test accuracy of default values mentioned in help text
bool test_printUsage_defaultValueAccuracy() {
    TestOutputCapture capture;
    const char* program_name = "defaults_test";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify specific default values are documented
    TEST_ASSERT_CONTAINS(output, "default: qkd_ed25519");  // prefix default
    TEST_ASSERT_CONTAINS(output, "default: 365");         // days default
    
    // Verify the defaults appear in context with their respective options
    size_t prefix_pos = output.find("--prefix");
    size_t prefix_default_pos = output.find("default: qkd_ed25519");
    size_t days_pos = output.find("--days");
    size_t days_default_pos = output.find("default: 365");
    
    // The defaults should appear after their respective options
    TEST_ASSERT_TRUE(prefix_pos != std::string::npos && prefix_default_pos > prefix_pos);
    TEST_ASSERT_TRUE(days_pos != std::string::npos && days_default_pos > days_pos);
    
    return true;
}

// Test help message structure and organization
bool test_printUsage_helpMessageStructure() {
    TestOutputCapture capture;
    const char* program_name = "structure_test";
    
    capture.startCapture();
    UsagePrinter::printUsage(program_name);
    capture.stopCapture();
    
    std::string output = capture.getCapturedOutput();
    
    // Verify logical order of sections
    size_t usage_pos = output.find("Usage:");
    size_t description_pos = output.find("Generate Ed25519 X.509 cert from QKD keys");
    size_t options_pos = output.find("Options:");
    
    // Usage should come first, then description, then options
    TEST_ASSERT_TRUE(usage_pos < description_pos);
    TEST_ASSERT_TRUE(description_pos < options_pos);
    
    // Verify proper spacing between sections
    TEST_ASSERT_CONTAINS(output, "\n\n");  // Should have blank lines for readability
    
    // Verify consistent indentation for options
    std::string::size_type pos = 0;
    int properly_indented_options = 0;
    while ((pos = output.find("  --", pos)) != std::string::npos) {
        properly_indented_options++;
        pos += 4;
    }
    TEST_ASSERT_GE(properly_indented_options, 8); // Should have at least 8 properly indented options
    
    return true;
}

// Test runner
int main() {
    std::cout << "Running UsagePrinter unit tests...\n\n";
    
    struct TestCase {
        const char* name;
        bool (*test_func)();
    };
    
    TestCase tests[] = {
        {"Standard Program Name", test_printUsage_standardProgramName},
        {"Contains All Options", test_printUsage_containsAllOptions},
        {"Contains Option Descriptions", test_printUsage_containsOptionDescriptions},
        {"Empty Program Name", test_printUsage_emptyProgramName},
        {"Null Program Name", test_printUsage_nullProgramName},
        {"Long Program Name", test_printUsage_longProgramName},
        {"Special Characters Program Name", test_printUsage_specialCharactersProgramName},
        {"Proper Formatting", test_printUsage_properFormatting},
        {"Multiple Calls", test_printUsage_multipleCalls},
        {"Output Completeness", test_printUsage_outputCompleteness},
        {"Certificate Terminology", test_printUsage_certificateTerminology},
        {"Static Method Behavior", test_printUsage_staticMethodBehavior},
        {"X.509 Fields Present", test_printUsage_x509FieldsPresent},
        {"Default Value Accuracy", test_printUsage_defaultValueAccuracy},
        {"Help Message Structure", test_printUsage_helpMessageStructure}
    };
    
    int passed = 0;
    int total = sizeof(tests) / sizeof(TestCase);
    
    for (int i = 0; i < total; i++) {
        std::cout << "Running test: " << tests[i].name << " ... ";
        if (tests[i].test_func()) {
            std::cout << "PASSED\n";
            passed++;
        } else {
            std::cout << "FAILED\n";
        }
    }
    
    std::cout << "\nTest Results: " << passed << "/" << total << " tests passed\n";
    
    if (passed == total) {
        std::cout << "All tests passed!\n";
        return 0;
    } else {
        std::cout << "Some tests failed.\n";
        return 1;
    }
}