# UsagePrinter Unit Tests

This directory contains comprehensive unit tests for the `UsagePrinter` class, specifically designed to validate the help message output functionality of the QKD certificate generator.

## Testing Framework

**Framework Used**: Custom lightweight testing framework
- No external dependencies required (no Google Test, Catch2, etc.)
- Built-in output capture mechanism for testing console output
- Simple assertion macros for clear test validation
- Self-contained test runner with detailed reporting

## Running Tests

### Quick Test Run
```bash
make test
```

### Manual Compilation and Execution
```bash
g++ -std=c++17 -Wall -Wextra -O2 -o tests/test_usage_printer tests/test_usage_printer.cpp usage_printer.cpp
./tests/test_usage_printer
```

### Build and Test Together
```bash
make test-all
```

## Test Coverage

The test suite provides comprehensive coverage across multiple dimensions:

### 1. **Basic Functionality Tests**
- **Standard Program Name**: Validates normal usage with typical program names
- **Static Method Behavior**: Confirms the static method works without instantiation

### 2. **Content Validation Tests**
- **Contains All Options**: Verifies all 10 command-line options are documented
- **Contains Option Descriptions**: Ensures all option descriptions are present and accurate
- **Certificate Terminology**: Validates Ed25519, X.509, QKD terminology usage
- **X.509 Fields Present**: Confirms all standard X.509 distinguished name fields are documented
- **Default Value Accuracy**: Verifies accuracy of documented default values

### 3. **Edge Case and Robustness Tests**
- **Empty Program Name**: Tests behavior with empty string input
- **Null Program Name**: Tests undefined behavior handling with null input
- **Long Program Name**: Validates handling of extremely long program names
- **Special Characters Program Name**: Tests program names with special characters (./,@,_,-)

### 4. **Output Quality and Structure Tests**
- **Proper Formatting**: Validates newlines, indentation, and structure
- **Output Completeness**: Ensures minimum content length and proper termination
- **Help Message Structure**: Verifies logical organization and section ordering
- **Multiple Calls**: Confirms consistent output across multiple invocations

### 5. **Certificate-Specific Validation**
- **QKD Integration**: Validates Quantum Key Distribution terminology
- **Ed25519 Algorithm**: Confirms elliptic curve cryptography references
- **X.509 Standard Compliance**: Ensures proper certificate field documentation

## Test Architecture

### Output Capture System
```cpp
class TestOutputCapture {
    // Redirects std::cout to internal buffer
    // Allows precise testing of console output
    // Provides clean restoration of original output stream
};
```

### Assertion Framework
- `TEST_ASSERT_CONTAINS(str, substr)`: String containment validation
- `TEST_ASSERT_GE(a, b)`: Numerical comparison validation
- `TEST_ASSERT_EQ(a, b)`: Equality validation
- Custom error reporting with line numbers

### Test Structure Pattern
Each test follows a consistent pattern:
1. **Setup**: Initialize test conditions and output capture
2. **Execute**: Call `UsagePrinter::printUsage()` with test parameters  
3. **Capture**: Collect and analyze the generated output
4. **Validate**: Assert expected content and structure
5. **Report**: Return success/failure status

## Validated Output Elements

The tests comprehensively validate:

### Command Line Options (10 total)
- `--key KEY` - Base64-encoded QKD key input
- `--prefix PREFIX` - Output filename prefix (default: qkd_ed25519)
- `--days DAYS` - Certificate validity period (default: 365)
- `--C COUNTRY` - X.509 Country Name field
- `--ST STATE` - X.509 State/Province Name field  
- `--L LOCALITY` - X.509 Locality Name field
- `--O ORG` - X.509 Organization Name field
- `--OU ORG_UNIT` - X.509 Organizational Unit field
- `--CN COMMON_NAME` - X.509 Common Name field
- `--help` - Help message display

### Message Structure
- Usage line with program name placeholder
- Clear description of Ed25519 X.509 certificate generation
- Properly formatted Options section
- Consistent indentation (2 spaces)
- Appropriate line breaks and spacing

### Technical Accuracy
- Correct cryptographic terminology (Ed25519, X.509, QKD)
- Accurate default values documentation
- Proper X.509 distinguished name field descriptions
- Example values where appropriate (e.g., "RO" for country)

## Test Maintenance

### Adding New Tests
1. Implement test function following naming convention: `test_printUsage_[feature]`
2. Add function declaration to header section
3. Include test case in the `tests[]` array in `main()`
4. Follow established assertion patterns

### Updating for New Features
When `UsagePrinter` functionality changes:
1. Update content validation tests for new options
2. Adjust expected output length calculations
3. Add specific tests for new features
4. Update terminology validation as needed

## Integration with Build System

The tests are fully integrated with the project's Makefile:
- `make test`: Compile and run tests
- `make test-all`: Build project and run tests
- `make clean_tests`: Clean test artifacts
- Automatic test target compilation with proper dependencies

## Expected Test Results

All tests should pass on a properly functioning `UsagePrinter` implementation. The test suite is designed to catch:
- Missing or incorrectly documented command-line options
- Formatting issues in help output
- Inconsistencies in terminology or descriptions
- Robustness problems with edge case inputs
- Structural problems in help message organization

**Success Criteria**: 15/15 tests passing with comprehensive output validation.