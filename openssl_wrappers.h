#pragma once
#include <memory>
#include <openssl/evp.h>
#include <openssl/x509.h>

// Smart pointer wrappers for OpenSSL objects
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* ptr) const {
        if (ptr) EVP_PKEY_free(ptr);
    }
};

struct X509_Deleter {
    void operator()(X509* ptr) const {
        if (ptr) X509_free(ptr);
    }
};

struct X509_NAME_Deleter {
    void operator()(X509_NAME* ptr) const {
        if (ptr) X509_NAME_free(ptr);
    }
};

struct BIO_Deleter {
    void operator()(BIO* ptr) const {
        if (ptr) BIO_free_all(ptr);
    }
};

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using X509_ptr = std::unique_ptr<X509, X509_Deleter>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, X509_NAME_Deleter>;
using BIO_ptr = std::unique_ptr<BIO, BIO_Deleter>;
