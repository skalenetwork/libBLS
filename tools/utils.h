/*
  Copyright (C) 2021- SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file utils.h
  @author Oleh Nikolaiev
  @date 2021
*/

#ifndef LIBBLS_UTILS_H
#define LIBBLS_UTILS_H

#include <array>
#include <atomic>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

static constexpr size_t BLS_MAX_COMPONENT_LEN = 77;

namespace libBLS {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

#define REQUIRE_OR_THROW( cond, msg )                                                     \
    do {                                                                                  \
        if ( !( cond ) )                                                                  \
            throw ThresholdUtils::IncorrectInput(                                         \
                std::string( msg ) + " @ " + __FILE__ ":" + std::to_string( __LINE__ ) ); \
    } while ( 0 )

#define THROW( msg )                      \
    throw ThresholdUtils::IncorrectInput( \
        std::string( msg ) + " @ " + __FILE__ ":" + std::to_string( __LINE__ ) );


class ThresholdUtils {
private:
    class Exception : public std::exception {
    protected:
        std::string what_str;

    public:
        Exception( const std::string& err_str ) { what_str = err_str; }

        virtual const char* what() const noexcept override { return what_str.c_str(); }
    };

public:
    class IsNotWellFormed : public Exception {
    public:
        IsNotWellFormed( const std::string& err_str ) : Exception( err_str ) {
            what_str = "IsNotWellFormedData : " + err_str;
        }
    };

    class ZeroSecretKey : public Exception {
    public:
        ZeroSecretKey( const std::string& err_str ) : Exception( err_str ) {
            what_str = "Secret key is equal to zero : " + err_str;
        }
    };

    class IncorrectInput : public Exception {
    public:
        IncorrectInput( const std::string& err_str ) : Exception( err_str ) {
            what_str = "Failed to proceed data : " + err_str;
        }
    };

    static std::atomic< bool > is_initialized;

    static void init();

    static void initCurve();

    static void initRAND();

    static void checkSigners( size_t _requiredSigners, size_t _totalSigners );

    static bool isStringNumber( const std::string& str );

    static int char2int( char _input );

    static std::string carray2Hex( const unsigned char* d, uint64_t len );

    static bool hex2carray( const char* _hex, uint64_t* _bin_len, uint8_t* _bin );

    static std::shared_ptr< std::vector< std::string > > SplitString(
        const std::shared_ptr< std::string >, const std::string& delim );

    static std::string bytesToHexString( const std::vector< uint8_t >& bytes );

    static std::vector< uint8_t > hexCStringToBytes( const char* hexStr );

    template < size_t N >
    static std::string bytesToHexString( const std::array< uint8_t, N >& bytes );

    template < size_t N >
    static std::array< uint8_t, N > hexCStringToBytesArray( const char* hexStr );

    template < class T >
    static void validatePointWithException( const T& point );

    /**
     * @brief Helper function that validates input char*
     * as a valid hex string, and returns its length.
     * @throw IncorrectInput if the input is not a valid hex string.
     */
    static size_t validateHexCString( const char* hexStr );

    static size_t validateDecimalCString( const char* decStr );
};

template < size_t N >
std::string ThresholdUtils::bytesToHexString( const std::array< uint8_t, N >& bytes ) {
    std::stringstream ss;
    ss << std::hex << std::setfill( '0' );

    for ( uint8_t byte : bytes ) {
        ss << std::setw( 2 ) << static_cast< int >( byte );  // Format each byte as 2-char hex
    }

    return ss.str();
}


template < size_t N >
std::array< uint8_t, N > ThresholdUtils::hexCStringToBytesArray( const char* hexStr ) {
    size_t characterCountNeeded = N * 2;
    if ( validateHexCString( hexStr ) < characterCountNeeded ) {
        throw IncorrectInput( "Hex string length must be at least 64 characters." );
    }

    std::array< uint8_t, N > bytes;

    // Convert hex string to byte array
    for ( size_t i = 0; i < characterCountNeeded; i += 2 ) {
        bytes[i / 2] = ( std::stoi( std::string( hexStr + i, 2 ), nullptr, 16 ) );
    }

    return bytes;
}

// Expose init() to libBLS users
inline void init() {
    ThresholdUtils::init();
}

}  // namespace libBLS

#endif  // LIBBLS_UTILS_H
