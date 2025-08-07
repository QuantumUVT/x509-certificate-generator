#include "command_line_parser.h"
#include "usage_printer.h"
#include <getopt.h>
#include <iostream>
#include <cstdlib>

int CommandLineParser::parseArguments(int argc, char* argv[], CertificateConfig& config) {
    static struct option long_options[] = {
        {"key", required_argument, 0, 'k'},
        {"prefix", required_argument, 0, 'p'},
        {"days", required_argument, 0, 'd'},
        {"C", required_argument, 0, 'c'},
        {"ST", required_argument, 0, 's'},
        {"L", required_argument, 0, 'l'},
        {"O", required_argument, 0, 'o'},
        {"OU", required_argument, 0, 'u'},
        {"CN", required_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "k:p:d:c:s:l:o:u:n:h", long_options, &option_index)) != -1) {
        switch (c) {
            case 'k':
                config.keys.push_back(std::string(optarg));
                break;
            case 'p':
                config.prefix = std::string(optarg);
                break;
            case 'd': {
                int days = std::atoi(optarg);
                if (days <= 0) {
                    std::cerr << "Error: Invalid days value: " << optarg << std::endl;
                    return 1;
                }
                config.days = days;
                break;
            }
            case 'c':
                config.country = std::string(optarg);
                break;
            case 's':
                config.state = std::string(optarg);
                break;
            case 'l':
                config.locality = std::string(optarg);
                break;
            case 'o':
                config.organization = std::string(optarg);
                break;
            case 'u':
                config.organizational_unit = std::string(optarg);
                break;
            case 'n':
                config.common_name = std::string(optarg);
                break;
            case 'h':
                UsagePrinter::printUsage(argv[0]);
                return 0;
            default:
                UsagePrinter::printUsage(argv[0]);
                return 1;
        }
    }
    
    if (config.keys.empty()) {
        std::cerr << "Error: At least one --key argument is required\n";
        UsagePrinter::printUsage(argv[0]);
        return 1;
    }
    
    return -1; // Continue processing
}
