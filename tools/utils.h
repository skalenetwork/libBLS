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

#include <third_party/cryptlite/sha256.h>
#include <array>
#include <atomic>
#include <functional>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

static constexpr size_t BLS_MAX_COMPONENT_LEN = 77;

// forward declare to avoid including folly headers in this header
namespace folly {
class CPUThreadPoolExecutor;
}

namespace libBLS {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;
constexpr size_t HASH_SIZE = 32;

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

    static constexpr size_t DEFAULT_NUM_THREADS = 0;

    static void initThreadPool( size_t _numThreads );

public:
#ifndef WITH_EMSCRIPTEN
    static std::unique_ptr< folly::CPUThreadPoolExecutor > thread_pool;
#endif

    static size_t numThreads;

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

    static void setNumThreads( size_t _numThreads );

    static void checkSigners( size_t _requiredSigners, size_t _totalSigners );

    static bool isStringNumber( const std::string& str );

    static int char2int( char _input );

    static std::string carray2Hex( const unsigned char* d, uint64_t len );

    static bool hex2carray( const char* _hex, uint64_t* _bin_len, uint8_t* _bin );

    static std::shared_ptr< std::vector< std::string > > SplitString(
        const std::string& str, const std::string& delim );

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

    /**
     * @brief Computes SHA256 hash of input data
     * @param data Input data to hash
     * @param out Output buffer (32 bytes) to store the hash
     * @note Uses OpenSSL EVP interface for hashing
     * Reuses a thread-local EVP_MD_CTX to avoid repeated allocations
     */
    static inline std::string sha256( std::string data ) {
        return cryptlite::sha256::hash_hex( data );
    }

    /**
     * @brief Executes tasks in parallel, merging the results and preserving the order of
     * `func` execution.
     * @param totalSize Total number of items to process.
     * @param func Function that processes a range [startIdx, endIdx) and returns a vector of
     * results.
     * @return A single vector containing all results from `func`, in the order of execution.
     * @note Uses a thread pool internally to parallelize the work.
     */
    template < typename T >
    static std::vector< T > executeInParallel( std::size_t totalSize,
        const std::function< std::vector< T >( std::size_t, std::size_t ) >& func );

private:
    /**
     * Schedules tasks that cover [0, totalSize) in contiguous ranges.
     * For i-th task, it calls runTask(startIdx, endIdx, taskIndex).
     * Blocks until all tasks finish.
     * Implemented in .cpp file with Folly, hidden from headers.
     * Used as an internal helper for executeInParallel.
     */
    static void parallel_for_ranges_blocking( std::size_t totalSize, std::size_t numThreads,
        std::size_t sizePerThread,
        const std::function< void( std::size_t, std::size_t, std::size_t ) >& runTask );
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


template < typename T >
std::vector< T > ThresholdUtils::executeInParallel( std::size_t totalSize,
    const std::function< std::vector< T >( std::size_t, std::size_t ) >& func ) {
#ifdef WITH_EMSCRIPTEN
    // single-threaded
    return func( 0, totalSize );
#else
    const std::size_t sizePerThread =
        ( totalSize + numThreads - 1 ) / ( numThreads ? numThreads : 1 );

    // Determine number of tasks (same chunking as before)
    const std::size_t tasks = ( totalSize == 0 || sizePerThread == 0 ) ?
                                  0 :
                                  ( ( totalSize + sizePerThread - 1 ) / sizePerThread );

    std::vector< std::vector< T > > chunks;
    chunks.resize( tasks );  // preserve submission order

    parallel_for_ranges_blocking( totalSize, numThreads, sizePerThread,
        [&]( std::size_t startIdx, std::size_t endIdx, std::size_t taskIndex ) {
            // Same per-chunk logic: compute chunk via func(start,end)
            chunks[taskIndex] = func( startIdx, endIdx );
        } );

    // Flatten results in submission order (equivalent to collectAll order)
    std::vector< T > finalResults;
    // Reserve is optional since total element count may equal totalSize, as in your code
    finalResults.reserve( totalSize );
    for ( auto& v : chunks ) {
        finalResults.insert( finalResults.end(), std::make_move_iterator( v.begin() ),
            std::make_move_iterator( v.end() ) );
    }
    return finalResults;
#endif
}

// Expose init() to libBLS users
inline void init() {
    ThresholdUtils::init();
}

}  // namespace libBLS

#endif  // LIBBLS_UTILS_H