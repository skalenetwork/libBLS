#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libff_backend {

class GTElement {
    libff::alt_bn128_GT value;
    
public:

    GTElement() {
        libff::alt_bn128_pp::init_public_params();
        value = libff::alt_bn128_GT::one();
    }

    GTElement(const libff::alt_bn128_GT& v) : value(v) {}

    GTElement operator*(const GTElement& other) const {
        return GTElement(value * other.value);
    }

    GTElement inverse() const {
        return GTElement(value.inverse());
    }

    bool operator==(const GTElement& other) const {
        return value == other.value;
    }

    bool operator!=(const GTElement& other) const {
        return value != other.value;
    }
};

}
