#include "./functions.hpp"

namespace libBLS::algebra {

std::pair< FqElement, FqElement > parseHint( const std::string& _hint ) {
    auto position = _hint.find( ":" );

    if ( position == std::string::npos || position > BLS_MAX_COMPONENT_LEN ||
         _hint.length() - position - 1 > BLS_MAX_COMPONENT_LEN ) {
        throw ThresholdUtils::IncorrectInput( "Misformatted hint" );
    }

    FqElement y = FqElement::fromString( _hint.substr( 0, position ), Base::DEC );
    FqElement shift_x = FqElement::fromString( _hint.substr( position + 1 ), Base::DEC );

    return std::make_pair( y, shift_x );
}

std::pair< G1Point, std::string > hashToG1withHint(
    const std::array< uint8_t, 32 >& hash_byte_arr ) {
    static const FqElement coeff_b =
        FqElement::fromString( std::string( AltBn128Contract::coeff_b_dec ), Base::DEC );
    static const std::string fq_euler_str = std::string( AltBn128Contract::fq_euler_dec );

    G1Point point;
    FqElement counter = FqElement::zero();
    FqElement x1 = hashToFq( hash_byte_arr );

    while ( true ) {
        // y^2 = x^3 + b
        FqElement y1_sqr = x1 ^ 3;
        y1_sqr = y1_sqr + coeff_b;

        FqElement euler = algebra::power( y1_sqr, fq_euler_str );

        if ( euler.isOne() || euler.isZero() ) {  // if y1_sqr is a square
            point.setX( x1 );
            FqElement temp_y = y1_sqr.sqrt();
            normalizeYCoordinate( temp_y );
            point.setY( temp_y );
            break;
        } else {
            counter = counter + FqElement::one();
            x1 = x1 + FqElement::one();
        }
    }

    point.setZ( FqElement::one() );

    FqElement counter_fq( counter );
    return std::make_pair( point, counter_fq.toString( Base::DEC ) );
}

G1Point hashToG1( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr ) {
    return hashToG1withHint( hash_byte_arr ).first;
}

G1Point hashToG1( const std::string& message ) {
    auto hash_bytes_arr = std::array< uint8_t, HASH_SIZE >();

    if ( message.length() > HASH_SIZE * 2 ) {
        throw std::runtime_error( "Hash string too long" );
    }

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( message.c_str(), &bin_len, hash_bytes_arr.data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return hashToG1( hash_bytes_arr );
}

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t ) {
    if ( idx.size() < t ) {
        throw ThresholdUtils::IncorrectInput( "not enough participants in the threshold group" );
    }

    std::vector< FrScalar > res( t );

    FrScalar w = FrScalar::one();

    for ( size_t i = 0; i < t; ++i ) {
        w *= FrScalar( idx.at( i ) );
    }

    for ( size_t i = 0; i < t; ++i ) {
        FrScalar v = FrScalar( idx.at( i ) );

        for ( size_t j = 0; j < t; ++j ) {
            if ( j != i ) {
                if ( FrScalar( idx.at( i ) ) == FrScalar( idx.at( j ) ) ) {
                    throw ThresholdUtils::IncorrectInput(
                        "during the interpolation, have same indexes in list of indexes" );
                }

                v *= ( FrScalar( idx.at( j ) ) - FrScalar( idx.at( i ) ) );  // calculating Lagrange
                                                                             // coefficients
            }
        }

        res.at( i ) = w * v.inverse();
    }

    std::vector< FrScalar > output;
    output.reserve( t );

    for ( size_t i = 0; i < t; ++i ) {
        output.push_back( FrScalar( res.at( i ) ) );
    }

    return output;
}


}  // namespace libBLS::algebra
