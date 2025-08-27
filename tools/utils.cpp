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

#include <tools/utils.h>
#include <iomanip>

#include "backends/algebra.hpp"

namespace libBLS {


std::atomic< bool > ThresholdUtils::is_initialized = false;

std::mutex initMutex;

void ThresholdUtils::initCurve() {
    std::lock_guard< std::mutex > lock( initMutex );
    if ( !is_initialized ) {
        algebra::initCurve();
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

}  // namespace libBLS
