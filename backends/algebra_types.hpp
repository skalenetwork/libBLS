#pragma once

namespace libBLS {

namespace algebra {

    // base for field element representation when converting to / from string
    enum class Base : std::size_t {
        DEC  = 10,
        HEXA = 16,
    };
}

    // allow libBLS users to use libBLS::Base directly
    using Base = algebra::Base;

}