#pragma once

class Application {
public:
    static int run(int argc, char* argv[]);
    
private:
    static void initializeOpenSSL();
    static void cleanupOpenSSL();
};
