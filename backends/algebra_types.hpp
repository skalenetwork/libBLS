#pragma once

#include "./interface/init.hpp"

namespace libBLS {

namespace algebra {

// ------------------- Define Backend Constants ------------------- //

constexpr size_t HASH_SIZE = 32;
constexpr size_t MAX_FIELD_ELEMENT_SIZE_BYTES = 32;

// base for field element representation when converting to / from string
enum class Base : std::size_t {
    DEC = 10,
    HEXA = 16,
};
}  // namespace algebra

// ------------------- Expose Backend Types ------------------- //

// allow libBLS users to use from libBLS namespace directly
using Base = algebra::Base;
using algebra::initCurve;
using algebra::MAX_FIELD_ELEMENT_SIZE_BYTES;

}  // namespace libBLS