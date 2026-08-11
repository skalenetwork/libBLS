#include <array>
#include <vector>

#include "AesGcmCipher.h"
#include "CipheredKey.h"
#include "backends/algebra.hpp"

namespace libBLS {


std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > CipheredKey::toBytes() const {
    std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > bytes;
    uint8_t* source = bytes.data();
    // set U component
    auto uBytes = U.toByteArray();
    std::memcpy( source, uBytes.data(), uBytes.size() );
    source += uBytes.size();
    // set V commponent
    std::memcpy( source, V.data(), V.size() );
    source += V.size();
    // set W component
    auto wBytes = W.toByteArray();
    std::memcpy( source, wBytes.data(), wBytes.size() );

    return bytes;
}


CipheredKey CipheredKey::fromBytes(
    std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > _bytes, bool _validate ) {
    std::array< uint8_t, G2_SIZE_BYTES > uBytes;
    std::array< uint8_t, AES_256_KEY_SIZE_BYTES > vBytes;
    std::array< uint8_t, G1_SIZE_BYTES > wBytes;

    uint8_t* offset = _bytes.data();
    // Get U bytes
    std::memcpy( uBytes.data(), offset, G2_SIZE_BYTES );
    offset += G2_SIZE_BYTES;
    // Get V bytes
    std::memcpy( vBytes.data(), offset, AES_256_KEY_SIZE_BYTES );
    offset += AES_256_KEY_SIZE_BYTES;
    // Get W bytes
    std::memcpy( wBytes.data(), offset, G1_SIZE_BYTES );

    // Convert to CipheredKey components
    algebra::G2Point U = algebra::G2Point::fromBytes( uBytes );
    algebra::G1Point W = algebra::G1Point::fromBytes( wBytes );

    // constructor performs validation
    return CipheredKey( U, vBytes, W, _validate );
}

void CipheredKey::validate() const {
    W.validate();
    U.validate();
}

CipheredKey CipheredKey::random() {
    algebra::G2Point U = algebra::G2Point::random();
    AES256Key V;
    if (RAND_bytes( V.data(), V.size() ) != 1) {
        throw std::runtime_error( "Failed to generate random AES key" );
    }
    algebra::G1Point W = algebra::G1Point::random();
    return CipheredKey( U, V, W );
}

std::string CipheredKey::getDecryptionShareInput() {
    U.toAffineCoordinates();
    return U.toString( Base::HEXA );
}

std::vector< std::string > CipheredKey::getDecryptionShareInputBatch(
    const std::vector< CipheredKey >& keys ) {
    std::vector< algebra::G2Point > U_points;
    U_points.reserve( keys.size() );
    for ( const auto& key : keys ) {
        U_points.push_back( key.U );
    }

    // batch convert all to affine coordinates
    toAffineVec( U_points );

    std::vector< std::string > res;
    res.reserve( keys.size() );
    for ( const auto& U : U_points ) {
        auto uSplitted = U.toString( Base::HEXA );
        res.push_back( uSplitted );
    }

    return res;
}


}  // namespace libBLS