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

#ifndef EMSCRIPTEN
// error: comparison of integer expressions of different signedness: ‘const int’ and ‘const long
// unsigned int’ [-Werror=sign-compare]
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/futures/Future.h>
#pragma GCC diagnostic pop
#endif

namespace libBLS {

size_t ThresholdUtils::numThreads = DEFAULT_NUM_THREADS;

#ifndef EMSCRIPTEN
std::unique_ptr< folly::CPUThreadPoolExecutor > ThresholdUtils::thread_pool = nullptr;
#endif

void ThresholdUtils::init() {
    initRAND();
    initCurve();

#ifndef EMSCRIPTEN
    // if numThreads was not set yet, try setting it to hardware concurrency
    if ( numThreads == 0 ) {
        numThreads = std::thread::hardware_concurrency();
        if ( numThreads == 0 ) {
            numThreads = 4;  // Fallback to 4 threads if hardware_concurrency cannot detect
        }
    }
    initThreadPool( numThreads );
#endif
}

void ThresholdUtils::initCurve() {
    static std::once_flag initFlag;
    std::call_once( initFlag, []() { algebra::initCurve(); } );
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

void ThresholdUtils::setNumThreads( size_t _numThreads ) {
    numThreads = _numThreads > 64 ? 64 : _numThreads;
}

void ThresholdUtils::initThreadPool( size_t _numThreads ) {
#ifndef EMSCRIPTEN
    static std::once_flag initFlag;
    std::call_once( initFlag, [_numThreads]() {
        thread_pool = std::make_unique< folly::CPUThreadPoolExecutor >( _numThreads );
    } );
#endif
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

bool ThresholdUtils::hex2carray(
    const char* _hex, uint64_t* _bin_written_len, uint8_t* _bin, uint64_t _bin_capacity ) {
    if ( _hex == nullptr || _bin_written_len == nullptr || _bin == nullptr ) {
        return false;
    }
    int len = strnlen( _hex, 2 * 1024 );

    if ( len % 2 == 1 ) {
        return false;
    }

    unsigned int byte_length = len / 2;

    if ( byte_length != _bin_capacity ) {
        return false;
    }

    *_bin_written_len = 0;

    for ( unsigned int i = 0; i < byte_length; i++ ) {
        int high = char2int( _hex[i * 2] );
        int low = char2int( _hex[i * 2 + 1] );
        if ( high < 0 || low < 0 ) {
            return false;
        }
        _bin[i] = ( unsigned char ) ( high * 16 + low );
    }
    *_bin_written_len = byte_length;
    return true;
}

std::shared_ptr< std::vector< std::string > > ThresholdUtils::SplitString(
    const std::string& str, const std::string& delim ) {
    std::vector< std::string > tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find( delim, prev );
        if ( pos == std::string::npos )
            pos = str.length();
        std::string token = str.substr( prev, pos - prev );
        if ( !token.empty() )
            tokens.push_back( token );
        prev = pos + delim.length();
    } while ( pos < str.length() && prev < str.length() );

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
    if ( hexStr == nullptr ) {
        throw IncorrectInput( "Hex string is null." );
    }

    size_t len = validateHexCString( hexStr );

    // Limit to 2MB hex string (1MB of decoded data)
    constexpr size_t MAX_HEX_STRING_LENGTH = 1024 * 1024 * 2;
    if ( len > MAX_HEX_STRING_LENGTH ) {
        throw IncorrectInput( "Hex string exceeds maximum allowed length." );
    }

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
        if ( !std::isxdigit( static_cast< unsigned char >( hexStr[i] ) ) ) {
            throw IncorrectInput(
                "Hex string contains invalid characters: " + std::string( 1, hexStr[i] ) );
        }
    }
    return len;
}

size_t ThresholdUtils::validateDecimalCString( const char* decStr ) {
    size_t len = std::strlen( decStr );

    // Ensure the string contains only valid hexadecimal characters
    for ( size_t i = 0; i < len; i++ ) {
        if ( !std::isdigit( static_cast< unsigned char >( decStr[i] ) ) ) {
            throw IncorrectInput(
                "Decimal string contains invalid characters: " + std::string( 1, decStr[i] ) );
        }
    }
    return len;
}


void ThresholdUtils::parallel_for_ranges_blocking( std::size_t totalSize, std::size_t numThreads,
    std::size_t sizePerThread,
    const std::function< void( std::size_t, std::size_t, std::size_t ) >& runTask ) {
    if ( totalSize == 0 )
        return;

#ifdef EMSCRIPTEN
    // single task - single-threaded execution
    runTask( 0, totalSize, 0 );
#else

    const std::size_t threads = std::max< std::size_t >( 1, numThreads );
    const std::size_t sp = std::max< std::size_t >( 1, sizePerThread );
    const std::size_t tasks = ( totalSize + sp - 1 ) / sp;

    folly::CPUThreadPoolExecutor pool( threads );

    std::vector< folly::Future< folly::Unit > > futures;
    futures.reserve( tasks );

    for ( std::size_t taskIndex = 0; taskIndex < tasks; ++taskIndex ) {
        const std::size_t startIdx = taskIndex * sp;
        const std::size_t endIdx = std::min( startIdx + sp, totalSize );

        futures.push_back( folly::via( &pool, [startIdx, endIdx, taskIndex, &runTask]() {
            runTask( startIdx, endIdx, taskIndex );
            return folly::Unit{};
        } ) );
    }

    folly::collectAll( futures ).get();  // block until all tasks complete
#endif
}

}  // namespace libBLS
