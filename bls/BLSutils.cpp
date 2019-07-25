
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

int BLSutils::sgn0 (libff::alt_bn128_Fq x) {
    int res = 1;
    std::string x_str = BLSutils::ConvertToString(x);
    std::string euler_str = BLSutils::ConvertToString(libff::alt_bn128_Fq(libff::alt_bn128_Fq::euler));
    if ( x_str > euler_str )
           res = -1;
    return res;
}



