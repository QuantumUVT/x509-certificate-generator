# Quantum-Derived X.509 Certificate Generator

A high-performance C++ tool built with OpenSSL and C++17 to generate Ed25519 X.509 certificates derived from Quantum Key Distribution (QKD) entropy.

## Features

- **Entropy-Based Key Generation**: Collects and processes entropy from multiple Base64-encoded QKD keys.
- **Ed25519 Security**: Uses SHA-256 for deterministic key derivation to create X.509 certificates with Ed25519 public keys.
- **X.509 Compliance**: Generates standard-compliant PEM-formatted certificates and private keys.
- **Customizable Attributes**: Full control over certificate validity (days) and standard X.509 fields (CN, O, OU, L, ST, C).
- **Quantum-Ready Design**: Designed for scenarios where traditional pseudo-random number generators (PRNGs) are supplemented or replaced by QKD-provided entropy.

## Prerequisites

- **C++ Compiler**: `g++` (supports C++17).
- **OpenSSL**: `libssl` and `libcrypto` (development headers).
- **Build System**: `make`.

### Installation on Ubuntu/Debian

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

## Build Instructions

To build the project, run:

```bash
make
```

This will create a binary named `cert_generator`.

### Other Build Commands

- `make clean`: Removes the `obj` directory and the `cert_generator` binary.
- `make clean-certs`: Deletes all generated `.pem` files in the current directory.
- `make clean-all`: Runs both `clean` and `clean-certs`.
- `make rebuild`: Cleans and rebuilds the project.

## Usage

The generator requires at least one Base64-encoded key (`--key`) to derive entropy.

### Basic Example

```bash
./cert_generator --key "SGVsbG8gd29ybGQhCg==" --CN "My Quantum App"
```

This will generate:
- `qkd_ed25519_cert.pem`
- `qkd_ed25519_key.pem`

### Full Example with Multiple Keys and Custom Fields

```bash
./cert_generator \
  --key "VGhpcyBpcyBhIHF1YW50dW0ga2V5IDE=" \
  --key "QW5vdGhlcmIgcXVhbnR1bSBrZXkgMg==" \
  --prefix "my_cert" \
  --days 730 \
  --C "US" \
  --ST "California" \
  --L "San Francisco" \
  --O "Quantum Labs" \
  --OU "Security Dept" \
  --CN "quantum.example.com"
```

## Options

| Option | Description | Default |
| :--- | :--- | :--- |
| `-k, --key` | Base64-encoded QKD key (can be used multiple times) | **Required** |
| `-p, --prefix` | Filename prefix for the cert and key | `qkd_ed25519` |
| `-d, --days` | Certificate validity in days | `365` |
| `-c, --C` | Country Name (e.g., US, RO) | None |
| `-s, --ST` | State or Province Name | None |
| `-l, --L` | Locality Name | None |
| `-o, --O` | Organization Name | None |
| `-u, --OU` | Organizational Unit Name | None |
| `-n, --CN` | Common Name (e.g., hostname or user name) | None |
| `-h, --help` | Show the help message | N/A |

## Project Structure

- `main.cpp`: Entry point.
- `application.cpp/h`: Manages OpenSSL initialization and the main application lifecycle.
- `certificate_generator.cpp/h`: Logic for creating the X.509 certificate and signing it.
- `key_generator.cpp/h`: Ed25519 key derivation from seeds.
- `entropy_processor.cpp/h`: SHA-256 hashing logic to process collective entropy.
- `base64_decoder.cpp/h`: Decodes the input QKD keys.
- `command_line_parser.cpp/h`: Argument parsing via `getopt_long`.
- `usage_printer.cpp/h`: Prints help instructions.
- `openssl_wrappers.h`: Smart pointers and helpers for OpenSSL RAII.
- `certificate_config.h`: Shared configuration structure.

## Security Note

This tool derives the Ed25519 private key from the provided entropy using SHA-256. Ensure that the source entropy (QKD keys) is handled securely and that the resulting `.pem` files are protected with appropriate file permissions.
