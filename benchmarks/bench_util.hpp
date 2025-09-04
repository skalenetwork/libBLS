#pragma once
#include <chrono>
#include <cstdint>
#include <random>
#include <string>
#include <vector>


// Simple RAII timer. Starts on construction; stops on destruction.
// Accumulates into an external double reference (milliseconds).
struct ScopedTimer {
    using clock = std::chrono::steady_clock;
    std::chrono::time_point< clock > start;
    double& acc_ms;
    bool stopped{ false };

    explicit ScopedTimer( double& acc ) : start( clock::now() ), acc_ms( acc ) {}

    ~ScopedTimer() { stop(); }

    void stop() {
        if ( stopped )
            return;
        auto end = clock::now();
        acc_ms += std::chrono::duration< double, std::milli >( end - start ).count();
        stopped = true;
    }
};


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
    std::size_t msg_bytes{ 256 };
    std::uint64_t rounds{ 100 };
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
        else if ( s == "--rounds" )
            a.rounds = static_cast< std::uint64_t >( std::stoull( next( i ) ) );
    }

    return a;
}