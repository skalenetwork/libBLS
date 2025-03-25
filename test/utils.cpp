#include "utils.h"
#include <dkg/dkg.h>
#include <threshold_encryption/threshold_encryption.h>


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