#include "base64_decoder.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdexcept>

std::vector<unsigned char> Base64Decoder::decode(const std::string& input) {
    if (input.empty()) {
        throw std::runtime_error("Empty Base64 input");
    }

    BIO* bio = BIO_new_mem_buf(input.c_str(), -1);
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for Base64 decoding");
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free(bio);
        throw std::runtime_error("Failed to create Base64 BIO filter");
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    // Allocate buffer with some extra space for safety
    std::vector<unsigned char> result(input.length() + 16);
    int decoded_size = BIO_read(bio, result.data(), result.size());
    
    BIO_free_all(bio);
    
    if (decoded_size < 0) {
        throw std::runtime_error("Base64 decode failed - invalid input format");
    }
    
    result.resize(decoded_size);
    return result;
}
