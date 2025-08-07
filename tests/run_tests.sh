#!/bin/bash
# Build and run tests

set -e

echo "Building tests..."
cd "$(dirname "$0")"

# Build the test executable
g++ -std=c++17 -Wall -Wextra -g -o test_command_line_parser \
    test_command_line_parser.cpp \
    ../command_line_parser.cpp \
    ../usage_printer.cpp \
    -lgtest -lgtest_main -pthread

echo "Running tests..."
./test_command_line_parser

echo "Tests completed successfully!"