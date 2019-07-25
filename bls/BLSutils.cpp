
#include <memory>
#include <iostream>
#include <string>

#include "BLSutils.h"

void BLSutils::initBLS() {
    static bool is_initialized = false;
    if (!is_initialized) {
        libff::init_alt_bn128_params();
        is_initialized = true;
    }
}



