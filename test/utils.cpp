#include "utils.h"
#include <dkg/dkg.h>
#include <openssl/rand.h>
#include <threshold_encryption/threshold_encryption.h>
#include <threshold_encryption/ThresholdEncryption.h>


keys generateKeys( size_t t, size_t n ) {
    libBLS::Dkg dkgTe( t, n );

    std::vector< libff::alt_bn128_Fr > poly = dkgTe.GeneratePolynomial();

    libff::alt_bn128_Fr zero_el = libff::alt_bn128_Fr::zero();

    libff::alt_bn128_Fr common_skey = dkgTe.PolynomialValue( poly, zero_el );

    libBLS::TEPrivateKey commonPrivate( common_skey );

    libBLS::TEPublicKey commonPublic( commonPrivate );

    std::vector< libff::alt_bn128_Fr > skeys = dkgTe.SecretKeyContribution( poly );
    std::vector< libBLS::TEPrivateKeyShare > secretKeys;
    std::vector< libBLS::TEPublicKeyShare > publicKeys;
    for ( size_t i = 0; i < n; i++ ) {
        secretKeys.emplace_back( libBLS::TEPrivateKeyShare( skeys[i], i + 1, t, n ) );
        publicKeys.emplace_back( libBLS::TEPublicKeyShare( secretKeys[i] ) );
    }

    return { commonPublic, commonPrivate, secretKeys, publicKeys };
}


std::string randomHexaString( size_t length ) {
    const static std::string hexadecimal = "0123456789abcdefABCDEF";

    std::string randomString;
    randomString.reserve( length );
    for ( size_t i = 0; i < length; ++i ) {
        randomString += hexadecimal[rand() % hexadecimal.size()];
    }
    return randomString;
}


std::vector< uint8_t > randomByteVec( size_t length ) {
    std::vector< uint8_t > bytes( length );
    RAND_bytes( bytes.data(), length );
    return bytes;
}


void spoilRandomChar( std::string& str, size_t numCharsToSpoil, char charToReplace ) {
    size_t chars = numCharsToSpoil;
    while ( chars >= 1 ) {
        str[rand() % str.length()] = charToReplace;
        chars--;
    }
}

libBLS::Ciphertext generateRandomCiphertext( size_t dataSize, keys& keys ) {
    std::vector< uint8_t > data = randomByteVec( dataSize + libBLS::RANDOM_SECRET_SIZE_BYTES );
    return libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );
}

void tamperCipheredKeyV( libBLS::CipheredKey& key ) {
    size_t randomIdxToTamper = rand() % key.V.size();
    key.V[randomIdxToTamper] = (key.V[randomIdxToTamper] + 1) % 256;
}