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

    @file BLSPrivateKeyShare.cpp
    @author Stan Kladko
    @date 2019
*/


using namespace std;



#include "BLSPrivateKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSignature.h"

#include  "tools/bls_glue.cpp"

BLSPrivateKeyShare::BLSPrivateKeyShare( const string& _key, size_t _requiredSigners, size_t _totalSigners )
    : totalSigners( _totalSigners ), requiredSigners( _requiredSigners ) {
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );



    privateKey = make_shared< libff::alt_bn128_Fr >( _key.c_str() );
    if ( *privateKey == libff::alt_bn128_Fr::zero() ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Secret key share is equal to zero or corrupt" ) );
    }
}


shared_ptr< BLSSigShare > BLSPrivateKeyShare::sign( shared_ptr< string > _msg, size_t _signerIndex ) {
    shared_ptr< signatures::Bls > obj;

    obj = make_shared< signatures::Bls >( signatures::Bls( requiredSigners, totalSigners ) );

    libff::alt_bn128_G1 hash = obj->Hashing( *_msg );

    auto ss = make_shared< libff::alt_bn128_G1 >( obj->Signing( hash, *privateKey ) );

    ss->to_affine_coordinates();

    auto s = make_shared< BLSSigShare >( ss, _signerIndex, requiredSigners, totalSigners );

    auto ts = s->toString();

    auto sig2 = make_shared< BLSSigShare >( ts, _signerIndex, requiredSigners, totalSigners );

    if ( *s->getSigShare() != *sig2->getSigShare() ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Sig shares do not match" ) );
    }


    return s;
}

shared_ptr< vector< shared_ptr< BLSPrivateKeyShare>>>  BLSPrivateKeyShare:: generateSampleKeys(
        size_t _requiredSigners, size_t _totalSigners ){
    vector< shared_ptr< BLSPrivateKeyShare>> keys;

    for (size_t i = 0; i < _requiredSigners; ++i){
        libff::alt_bn128_Fr cur_key = libff::alt_bn128_Fr::random_element();

        while (cur_key == libff::alt_bn128_Fr::zero()) {
            cur_key = libff::alt_bn128_Fr::random_element();
        }

       string key_str = ConvertToString(cur_key);

         shared_ptr< BLSPrivateKeyShare> key_ptr = make_shared< BLSPrivateKeyShare>(key_str, _requiredSigners, _totalSigners );
         keys.push_back(key_ptr);
    }

    return make_shared< vector< shared_ptr< BLSPrivateKeyShare>>>(keys);
}

std::shared_ptr< libff::alt_bn128_Fr >  BLSPrivateKeyShare::getPrivateKey() const {
    return privateKey;
}