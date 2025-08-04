#pragma once

#include "gt.hpp"
#include "g1.hpp"
#include "g2.hpp"

namespace libff_backend {

GTElement pairing(const G1Point& g1, const G2Point& g2) {
    return GTElement(libff::alt_bn128_ate_reduced_pairing( g1.value, g2.value));
}

}

