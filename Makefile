CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto
TARGET = cert_generator
SRCDIR = .
OBJDIR = obj

# Source files
SOURCES = main.cpp \
          application.cpp \
          base64_decoder.cpp \
          entropy_processor.cpp \
          key_generator.cpp \
          certificate_generator.cpp \
          usage_printer.cpp \
          command_line_parser.cpp

# Object files
OBJECTS = $(SOURCES:%.cpp=$(OBJDIR)/%.o)

# Default target
all: $(TARGET)

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link target
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $(TARGET)

# Clean build files
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Clean generated certificates and keys
clean-certs:
	rm -f *.pem

# Clean everything
clean-all: clean clean-certs

# Rebuild
rebuild: clean all

.PHONY: all clean clean-certs clean-all rebuild test clean_tests

# Test targets
test: test_command_line_parser
	cd tests && ./test_command_line_parser

test_command_line_parser: tests/test_command_line_parser.cpp command_line_parser.cpp usage_printer.cpp
	g++ -std=c++17 -Wall -Wextra -g -o tests/test_command_line_parser tests/test_command_line_parser.cpp command_line_parser.cpp usage_printer.cpp -lgtest -lgtest_main -pthread

# Test targets
test: tests/test_usage_printer
	@echo "Running UsagePrinter unit tests..."
	@./tests/test_usage_printer

tests/test_usage_printer: tests/test_usage_printer.cpp usage_printer.h usage_printer.cpp
	@mkdir -p tests
	$(CXX) $(CXXFLAGS) -o $@ tests/test_usage_printer.cpp usage_printer.cpp

clean_tests:
	rm -f tests/test_usage_printer

# Run tests as part of build verification
test-all: $(TARGET) test
	@echo "Build and tests completed successfully!"
