#pragma once
#include "benchmarks/ScopedTimer.hpp"
#include <cstdint>
#include <random>
#include <string>
#include <vector>

inline std::vector< std::uint8_t > make_msg( std::size_t bytes, std::uint64_t seed = 1337 ) {
    std::mt19937_64 rng( seed );
    std::vector< std::uint8_t > m( bytes );
    for ( auto& b : m )
        b = static_cast< std::uint8_t >( rng() );
    return m;
}


// Tiny CLI args parser for our bench
struct BenchArgs {
    int t{ 3 };
    int n{ 5 };
    size_t msg_bytes{ 256 };
    size_t numTxs{ 1 };

};


inline BenchArgs parse_args( int argc, char** argv ) {
    BenchArgs a;

    for ( int i = 1; i < argc; ++i ) {
        std::string s = argv[i];
        auto next = [&]( int& i ) {
            return ( i + 1 < argc ) ? std::string( argv[++i] ) : std::string();
        };
        if ( s == "--t" )
            a.t = std::stoi( next( i ) );
        else if ( s == "--n" )
            a.n = std::stoi( next( i ) );
        else if ( s == "--msg" )
            a.msg_bytes = static_cast< std::size_t >( std::stoul( next( i ) ) );
        else if ( s == "--numTxs" )
            a.numTxs = static_cast< std::size_t >( std::stoul( next( i ) ) );
    }

    return a;
}

inline void print_args( const BenchArgs& args ) {
    std::cout << "Benchmarking Threshold Encryption with parameters:\n";
    std::cout << "  - t (required signers = number of shares per tx): " << args.t << "\n";
    std::cout << "  - n (total signers): " << args.n << "\n";
    std::cout << "  - message size (bytes): " << args.msg_bytes << "\n";
    std::cout << "  - number of txs: " << args.numTxs << "\n";
    std::cout << "  - backend: " << LIBBLS_BACKEND_NAME << "\n";
}

inline void print_progress( int currentIteration, int totalIterations ) {
    std::cout << "\rProgress: " << ( float ) currentIteration / totalIterations * 100 << "%"
              << std::flush;
}