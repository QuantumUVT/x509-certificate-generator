#pragma once
#include "certificate_config.h"

class CommandLineParser {
public:
    static int parseArguments(int argc, char* argv[], CertificateConfig& config);
};
