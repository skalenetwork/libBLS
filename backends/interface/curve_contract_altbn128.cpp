#include "./curve_contract_altbn128.hpp"
#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

const FqElement& AltBn128Contract::coeffB() {
    static const FqElement coeff_b = FqElement::fromString( std::string(AltBn128Contract::coeff_b_dec), Base::DEC );
    return coeff_b;
}

}  // namespace libBLS::algebra
