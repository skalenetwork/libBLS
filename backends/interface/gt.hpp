#pragma once

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

namespace libBLS {
namespace algebra {

class GTElement {
    
public:

#ifdef MCL
#else
    libff::alt_bn128_GT value;
    GTElement(const libff::alt_bn128_GT& v) : value(v) {}
#endif

    GTElement();

    GTElement operator*(const GTElement& other) const;
    GTElement inverse() const;
    bool operator==(const GTElement& other) const;
    bool operator!=(const GTElement& other) const;
};

} // namespace algebra
} // namespace libBLS
