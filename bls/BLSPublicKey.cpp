/*
    Copyright (C) 2019 SKALE Labs

    This file is part of skale-consensus.

    skale-consensus is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    skale-consensus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with skale-consensus.  If not, see <https://www.gnu.org/licenses/>.

    @file BLSPublicKey.cpp
    @author Stan Kladko
    @date 2019
*/


#include <stdint.h>
#include <string>

using namespace std;


#include "BLSSignature.h"
#include "BLSPublicKey.h"


BLSPublicKey::BLSPublicKey( const string& k1, const string& k2, const string& k3, const string& k4,
    size_t _totalSigners, size_t _requiredSigners )
    : totalSigners( _totalSigners ), requiredSigners( _requiredSigners )  {
    BLSSignature::checkSigners( _totalSigners, _requiredSigners );


    libffPublicKey = make_shared< libff::alt_bn128_G2 >();

    libffPublicKey->X.c0 = libff::alt_bn128_Fq( k1.c_str() );
    libffPublicKey->X.c1 = libff::alt_bn128_Fq( k2.c_str() );
    libffPublicKey->Y.c0 = libff::alt_bn128_Fq( k3.c_str() );
    libffPublicKey->Y.c1 = libff::alt_bn128_Fq( k4.c_str() );
    libffPublicKey->Z.c0 = libff::alt_bn128_Fq::one();
    libffPublicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if ( libffPublicKey->X.c0 == libff::alt_bn128_Fq::zero() ||
         libffPublicKey->X.c1 == libff::alt_bn128_Fq::zero() ||
         libffPublicKey->Y.c0 == libff::alt_bn128_Fq::zero() ||
         libffPublicKey->Y.c1 == libff::alt_bn128_Fq::zero() ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Public Key is equal to zero or corrupt" ) );
    }
}
shared_ptr< libff::alt_bn128_G2 >BLSPublicKey::getLibffPublicKey() const {
    return libffPublicKey;
}
size_t BLSPublicKey::getTotalSigners() const {
    return totalSigners;
}
size_t BLSPublicKey::getRequiredSigners() const {
    return requiredSigners;
}


void BLSPublicKey::verifySig( shared_ptr< string > _msg) {

    shared_ptr< signatures::Bls > obj;

    obj = make_shared< signatures::Bls >( signatures::Bls( requiredSigners, totalSigners ) );

    libff::alt_bn128_G1 hash = obj->Hashing( *_msg );

    // verify signature here - throw runtime_error if signature does not verify


}