#ifdef LIBFF

#pragma once
#include <gmpxx.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <libff/common/utils.hpp>
#include <string>
#include <vector>

#include "backends/algebra_types.hpp"
#include "tools/utils.h"


namespace libBLS::algebra {

inline std::string convertHexToDec( const std::string& hex_str ) {
    try {
        // construct from base 16
        mpz_class dec( hex_str, libBLS::BASE_HEXA );

        // convert to base 10
        return dec.get_str( libBLS::BASE_DEC );

    } catch ( std::exception& e ) {
        throw ThresholdUtils::IncorrectInput( e.what() );
    } catch ( ... ) {
        throw ThresholdUtils::IncorrectInput( "Exception in convert hex to dec" );
    }
}

}  // namespace libBLS::algebra

#endif // LIBFF