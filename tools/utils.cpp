/*
  Copyright (C) 2021- SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file utils.cpp
  @author Oleh Nikolaiev
  @date 2021
*/

#include <mutex>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <gmpxx.h>
#include <tools/utils.h>
#include <iomanip>


namespace libBLS {


std::atomic< bool > ThresholdUtils::is_initialized = false;

std::mutex initMutex;

void ThresholdUtils::initCurve() {
    std::lock_guard< std::mutex > lock( initMutex );
    if ( !is_initialized ) {
        libff::init_alt_bn128_params();
        is_initialized = true;
    }
}

void ThresholdUtils::initRAND() {
    static std::once_flag initFlag;
    std::call_once( initFlag, []() {
        // initialize random number generator (for IVs)
        if ( RAND_load_file( "/dev/urandom", 32 ) != 32 ) {
            throw std::runtime_error( "Failed to initialize random number generator" );
        }
    } );
}

void ThresholdUtils::checkSigners( size_t _requiredSigners, size_t _totalSigners ) {
    if ( _requiredSigners > _totalSigners ) {
        throw IsNotWellFormed( "_requiredSigners > _totalSigners" );
    }

    if ( _totalSigners == 0 ) {
        throw IncorrectInput( "_totalSigners == 0" );
    }

    if ( _requiredSigners == 0 ) {
        throw IncorrectInput( "_requiredSigners == 0" );
    }
}

std::vector< std::string > ThresholdUtils::G2ToString( libff::alt_bn128_G2 elem, int base ) {
    if ( !elem.is_special() )
        elem.to_affine_coordinates();
    return { fieldElementToString( elem.X.c0, base ), fieldElementToString( elem.X.c1, base ),
        fieldElementToString( elem.Y.c0, base ), fieldElementToString( elem.Y.c1, base ) };
}

std::array< uint8_t, G2_SIZE_BYTES > ThresholdUtils::G2ToBytesArray( libff::alt_bn128_G2 elem ) {
    std::array< uint8_t, G2_SIZE_BYTES > G2Bytes;

    if ( !elem.is_special() )
        elem.to_affine_coordinates();
    uint8_t* dest = G2Bytes.data();

    // Get x.c0 bytes
    auto x_c0_bytes = fieldElementToBytes( elem.X.c0 );
    std::memcpy( dest, x_c0_bytes.data(), MAX_FIELD_ELEMENT_SIZE_BYTES );
    dest += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get x.c1 bytes
    auto x_c1_bytes = fieldElementToBytes( elem.X.c1 );
    std::memcpy( dest, x_c1_bytes.data(), MAX_FIELD_ELEMENT_SIZE_BYTES );
    dest += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get y.c0 bytes
    auto y_c0_bytes = fieldElementToBytes( elem.Y.c0 );
    std::memcpy( dest, y_c0_bytes.data(), MAX_FIELD_ELEMENT_SIZE_BYTES );
    dest += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get y.c1 bytes
    auto y_c1_bytes = fieldElementToBytes( elem.Y.c1 );
    std::memcpy( dest, y_c1_bytes.data(), MAX_FIELD_ELEMENT_SIZE_BYTES );

    return G2Bytes;
}

std::vector< uint8_t > ThresholdUtils::G2ToBytes( libff::alt_bn128_G2 elem ) {
    std::array< uint8_t, G2_SIZE_BYTES > G2Bytes = G2ToBytesArray( elem );
    return std::vector< uint8_t >( G2Bytes.begin(), G2Bytes.end() );
}

libff::alt_bn128_G2 ThresholdUtils::bytesToG2( std::array< uint8_t, G2_SIZE_BYTES > bytes ) {
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > currentField;

    libff::alt_bn128_G2 ret;
    ret.Z = libff::alt_bn128_Fq2::one();

    uint8_t* source = bytes.data();
    // Get x.c0
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.X.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get x.c1
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.X.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get y.c0
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.Y.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get y.c1
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.Y.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );

    return ret;
}

libff::alt_bn128_G2 ThresholdUtils::bytesToG2( std::vector< uint8_t > bytes ) {
    if ( bytes.size() != G2_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Incorrect number of bytes" );
    }

    std::array< uint8_t, G2_SIZE_BYTES > G2Bytes;
    std::copy( bytes.begin(), bytes.end(), G2Bytes.begin() );

    return bytesToG2( G2Bytes );
}

std::array< uint8_t, G1_SIZE_BYTES > ThresholdUtils::G1ToBytes( libff::alt_bn128_G1 elem ) {
    std::array< uint8_t, G1_SIZE_BYTES > G1Bytes;

    if ( !elem.is_special() )
        elem.to_affine_coordinates();
    uint8_t* source = G1Bytes.data();

    // Get X bytes
    auto x_bytes = fieldElementToBytes( elem.X );
    std::memcpy( source, x_bytes.data(), MAX_FIELD_ELEMENT_SIZE_BYTES );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get Y bytes
    auto y_bytes = fieldElementToBytes( elem.Y );
    std::memcpy( source, y_bytes.data(), MAX_FIELD_ELEMENT_SIZE_BYTES );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    return G1Bytes;
}

libff::alt_bn128_G1 ThresholdUtils::bytesToG1( std::array< uint8_t, G1_SIZE_BYTES > bytes ) {
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > currentField;

    libff::alt_bn128_G1 ret;
    ret.Z = libff::alt_bn128_Fq::one();

    uint8_t* source = bytes.data();

    // Get X
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.X = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get Y
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.Y = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );

    return ret;
}


std::string ThresholdUtils::convertHexToDec( const std::string& hex_str ) {
    try {
        // construct from base 16
        mpz_class dec( hex_str, libBLS::BASE_HEXA );

        // convert to base 10
        return dec.get_str( libBLS::BASE_DEC );

    } catch ( std::exception& e ) {
        throw IncorrectInput( e.what() );
    } catch ( ... ) {
        throw IncorrectInput( "Exception in convert hex to dec" );
    }
}

std::string ThresholdUtils::convertDecToHex( std::string dec, int numBytes ) {
    // construct from base 10
    mpz_class num( dec, libBLS::BASE_DEC );
    // convert to base 16
    std::string result = num.get_str( libBLS::BASE_HEXA );
    // pad with leading zeroes
    int n_zeroes = numBytes * 2 - result.length();
    result.insert( 0, n_zeroes, '0' );
    return result;
}

libff::alt_bn128_G2 ThresholdUtils::stringToG2( const std::string& str ) {
    if ( str.size() != 256 ) {
        throw IncorrectInput( "Wrong string size to convert to G2" );
    }

    libff::alt_bn128_G2 ret;

    ret.Z = libff::alt_bn128_Fq2::one();

    ret.X.c0 =
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 0, 64 ) ).c_str() );
    ret.X.c1 =
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 64, 64 ) ).c_str() );
    ret.Y.c0 =
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 128, 64 ) ).c_str() );
    ret.Y.c1 = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 192, std::string::npos ) ).c_str() );

    return ret;
}

libff::alt_bn128_G1 ThresholdUtils::stringToG1( const std::string& str ) {
    if ( str.size() != 128 ) {
        throw IncorrectInput( "Wrong string size to convert to G1" );
    }

    libff::alt_bn128_G1 ret;

    ret.Z = libff::alt_bn128_Fq::one();
    ret.X = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 0, 64 ) ).c_str() );
    ret.Y = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 64, 64 ) ).c_str() );

    return ret;
}

std::vector< libff::alt_bn128_Fr > ThresholdUtils::LagrangeCoeffs(
    const std::vector< size_t >& idx, size_t t ) {
    if ( idx.size() < t ) {
        throw IncorrectInput( "not enough participants in the threshold group" );
    }

    std::vector< libff::alt_bn128_Fr > res( t );

    libff::alt_bn128_Fr w = libff::alt_bn128_Fr::one();

    for ( size_t i = 0; i < t; ++i ) {
        w *= libff::alt_bn128_Fr( idx[i] );
    }

    for ( size_t i = 0; i < t; ++i ) {
        libff::alt_bn128_Fr v = libff::alt_bn128_Fr( idx[i] );

        for ( size_t j = 0; j < t; ++j ) {
            if ( j != i ) {
                if ( libff::alt_bn128_Fr( idx[i] ) == libff::alt_bn128_Fr( idx[j] ) ) {
                    throw IncorrectInput(
                        "during the interpolation, have same indexes in list of indexes" );
                }

                v *= ( libff::alt_bn128_Fr( idx[j] ) -
                       libff::alt_bn128_Fr( idx[i] ) );  // calculating Lagrange coefficients
            }
        }

        res[i] = w * v.invert();
    }

    return res;
}

libff::alt_bn128_Fq ThresholdUtils::HashToFq(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr ) {
    libff::bigint< libff::alt_bn128_q_limbs > from_hex;

    std::vector< uint8_t > hex( 64 );
    for ( size_t i = 0; i < 32; ++i ) {
        hex[2 * i] = static_cast< int >( hash_byte_arr->at( i ) ) / 16;
        hex[2 * i + 1] = static_cast< int >( hash_byte_arr->at( i ) ) % 16;
    }
    mpn_set_str( from_hex.data, hex.data(), 64, 16 );

    libff::alt_bn128_Fq ret_val( from_hex );

    return ret_val;
}

libff::alt_bn128_G1 ThresholdUtils::HashtoG1(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr ) {
    libff::alt_bn128_Fq x1( HashToFq( hash_byte_arr ) );

    libff::alt_bn128_G1 result;

    while ( true ) {
        libff::alt_bn128_Fq y1_sqr = x1 ^ 3;
        y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

        libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

        if ( euler == libff::alt_bn128_Fq::one() ||
             euler == libff::alt_bn128_Fq::zero() ) {  // if y1_sqr is a square
            result.X = x1;
            libff::alt_bn128_Fq temp_y = y1_sqr.sqrt();

            mpz_class y, y_neg;
            temp_y.as_bigint().to_mpz( y.get_mpz_t() );
            // convert -y in Fq first, then convert to mpz
            ( -temp_y ).as_bigint().to_mpz( y_neg.get_mpz_t() );

            if ( y < y_neg ) {
                temp_y = -temp_y;
            }

            result.Y = temp_y;
            break;
        } else {
            x1 = x1 + 1;
        }
    }
    result.Z = libff::alt_bn128_Fq::one();

    return result;
}

libff::alt_bn128_G1 ThresholdUtils::HashtoG1( const std::string& message ) {
    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( message.c_str(), &bin_len, hash_bytes_arr->data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return ThresholdUtils::HashtoG1( hash_bytes_arr );
}

bool ThresholdUtils::isStringNumber( const std::string& str ) {
    if ( str.at( 0 ) == '0' && str.length() > 1 )
        return false;
    for ( const char& c : str ) {
        if ( !( c >= '0' && c <= '9' ) ) {
            return false;
        }
    }
    return true;
}

std::string ThresholdUtils::carray2Hex( const unsigned char* d, uint64_t len ) {
    std::string _hexArray;
    _hexArray.resize( 2 * len );

    char hexval[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
        'f' };

    for ( uint64_t j = 0; j < len; j++ ) {
        _hexArray[j * 2] = hexval[( ( d[j] >> 4 ) & 0xF )];
        _hexArray[j * 2 + 1] = hexval[( d[j] ) & 0x0F];
    }

    return _hexArray;
}

int ThresholdUtils::char2int( char _input ) {
    if ( _input >= '0' && _input <= '9' )
        return _input - '0';
    if ( _input >= 'A' && _input <= 'F' )
        return _input - 'A' + 10;
    if ( _input >= 'a' && _input <= 'f' )
        return _input - 'a' + 10;
    return -1;
}

bool ThresholdUtils::hex2carray( const char* _hex, uint64_t* _bin_len, uint8_t* _bin ) {
    int len = strnlen( _hex, 2 * 1024 );

    if ( len % 2 == 1 ) {
        return false;
    }
    *_bin_len = len / 2;
    for ( int i = 0; i < len / 2; i++ ) {
        int high = char2int( ( char ) _hex[i * 2] );
        int low = char2int( ( char ) _hex[i * 2 + 1] );
        if ( high < 0 || low < 0 ) {
            return false;
        }
        _bin[i] = ( unsigned char ) ( high * 16 + low );
    }
    return true;
}

std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > ThresholdUtils::ParseHint(
    const std::string& _hint ) {
    auto position = _hint.find( ":" );

    if ( position == std::string::npos || position > BLS_MAX_COMPONENT_LEN ||
         _hint.length() - position - 1 > BLS_MAX_COMPONENT_LEN ) {
        throw IncorrectInput( "Misformatted hint" );
    }

    libff::alt_bn128_Fq y( _hint.substr( 0, position ).c_str() );
    libff::alt_bn128_Fq shift_x( _hint.substr( position + 1 ).c_str() );

    return std::make_pair( y, shift_x );
}

std::shared_ptr< std::vector< std::string > > ThresholdUtils::SplitString(
    std::shared_ptr< std::string > str, const std::string& delim ) {
    if ( !str ) {
        throw IncorrectInput( " str pointer is null in SplitString " );
    }

    std::vector< std::string > tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str->find( delim, prev );
        if ( pos == std::string::npos )
            pos = str->length();
        std::string token = str->substr( prev, pos - prev );
        if ( !token.empty() )
            tokens.push_back( token );
        prev = pos + delim.length();
    } while ( pos < str->length() && prev < str->length() );

    return std::make_shared< std::vector< std::string > >( tokens );
}

std::string ThresholdUtils::bytesToHexString( const std::vector< uint8_t >& bytes ) {
    std::stringstream ss;
    ss << std::hex << std::setfill( '0' );

    for ( uint8_t byte : bytes ) {
        ss << std::setw( 2 ) << static_cast< int >( byte );  // Format each byte as 2-char hex
    }

    return ss.str();
}

std::string ThresholdUtils::bytesToHexString(
    const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& bytes ) {
    std::stringstream ss;
    ss << std::hex << std::setfill( '0' );

    for ( uint8_t byte : bytes ) {
        ss << std::setw( 2 ) << static_cast< int >( byte );  // Format each byte as 2-char hex
    }

    return ss.str();
}

std::vector< uint8_t > ThresholdUtils::hexCStringToBytes( const char* hexStr ) {
    size_t len = validateHexCString( hexStr );

    std::vector< uint8_t > bytes( len / 2 );

    // Convert hex string to byte array
    for ( size_t i = 0; i < len; i += 2 ) {
        bytes[i / 2] = ( std::stoi( std::string( hexStr + i, 2 ), nullptr, 16 ) );
    }

    return bytes;
}

size_t ThresholdUtils::validateHexCString( const char* hexStr ) {
    size_t len = std::strlen( hexStr );

    // Ensure the hex string length is even
    if ( len % 2 != 0 ) {
        throw IncorrectInput( "Hex string length must be even." );
    }

    // Ensure the string contains only valid hexadecimal characters
    for ( size_t i = 0; i < len; i++ ) {
        if ( !std::isxdigit( hexStr[i] ) ) {
            throw IncorrectInput( "Hex string contains invalid characters." + hexStr[i] );
        }
    }
    return len;
}

void ThresholdUtils::validateG1( const libff::alt_bn128_G1& point ) {
    if ( point.is_zero() ) {
        throw IncorrectInput( "Point is zero" );
    }
    if ( !point.is_well_formed() ) {
        throw IncorrectInput( "Point is not well formed" );
    }
    if ( libff::alt_bn128_G1::order() * point != libff::alt_bn128_G1::zero() ) {
        throw IncorrectInput( "Point is not on the group" );
    }
}

void ThresholdUtils::validateG2( const libff::alt_bn128_G2& point ) {
    if ( point.is_zero() ) {
        throw IncorrectInput( "Point is zero" );
    }
    if ( !point.is_well_formed() ) {
        throw IncorrectInput( "Point is not well formed" );
    }
    if ( libff::alt_bn128_G2::order() * point != libff::alt_bn128_G2::zero() ) {
        throw IncorrectInput( "Point is not on the group" );
    }
}

}  // namespace libBLS
