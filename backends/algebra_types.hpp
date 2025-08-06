#pragma once

namespace libBLS {

namespace algebra {

    constexpr size_t HASH_SIZE = 32;
    constexpr size_t MAX_FIELD_ELEMENT_SIZE_BYTES = 32;

    // base for field element representation when converting to / from string
    enum class Base : std::size_t {
        DEC  = 10,
        HEXA = 16,
    };
}

    // allow libBLS users to use libBLS::Base directly
    using Base = algebra::Base;

}