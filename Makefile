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

.PHONY: all clean clean-certs clean-all rebuild
