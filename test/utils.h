#ifndef UTILS_H
#define UTILS_H

#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include "backends/algebra.hpp"
#include <chrono>

#define TIMER( variable, code_block )                                                   \
    auto start_##variable = std::chrono::high_resolution_clock::now();                  \
    code_block auto end_##variable = std::chrono::high_resolution_clock::now();         \
    auto duration_##variable = std::chrono::duration_cast< std::chrono::microseconds >( \
        end_##variable - start_##variable )                                             \
                                   .count();                                            \
    variable += duration_##variable;

struct keys {
    libBLS::TEPublicKey commonPublic;
    libBLS::TEPrivateKey commonPrivate;
    std::vector< libBLS::TEPrivateKeyShare > secretKeys;
    std::vector< libBLS::TEPublicKeyShare > publicKeys;
};


/// Should be used to init all tests - initializes the curve
struct GlobalConfig {
    GlobalConfig() {
        // runs before any test
        libBLS::initCurve();
    }
};


keys generateKeys( size_t t, size_t n );

std::string randomHexaString( size_t length );

std::vector< uint8_t > randomByteVec( size_t length );

void spoilRandomChar( std::string& str, size_t numCharsToSpoil, char charToReplace );

libBLS::Ciphertext generateRandomCiphertext( size_t dataSize, keys& keys );

void tamperCipheredKeyV( libBLS::CipheredKey& key );


#endif