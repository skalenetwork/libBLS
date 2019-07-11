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

BLSPublicKey::BLSPublicKey(  const libff::alt_bn128_Fr& skey, size_t _totalSigners, size_t _requiredSigners )
        : totalSigners( _totalSigners ), requiredSigners( _requiredSigners ) {

    libffPublicKey = make_shared <libff::alt_bn128_G2 > (skey * libff::alt_bn128_G2::one());
}

BLSPublicKey::BLSPublicKey(  const libff::alt_bn128_G2 pkey){
    libffPublicKey = make_shared<libff::alt_bn128_G2>(pkey);
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

bool BLSPublicKey::VerifySig ( std::shared_ptr< std::string > _msg, std::shared_ptr< BLSSignature > sign_ptr, size_t _requiredSigners, size_t _totalSigners){
    std::shared_ptr< signatures::Bls > obj;

    obj = std::make_shared< signatures::Bls >( signatures::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->Verification ( *_msg, *(sign_ptr->getSig()), *libffPublicKey);
    return res;
}

std::shared_ptr <BLSPublicKey> BLSPublicKey::gluePublicKey (std::map<size_t, std::shared_ptr<BLSPublicKeyShare> > koefs_pkeys_map){
    signatures::Bls obj = signatures::Bls( requiredSigners, totalSigners );

    vector< size_t > participatingNodes;
    vector< libff::alt_bn128_G1 > shares;

    for ( auto&& item : koefs_pkeys_map ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
    }

    vector< libff::alt_bn128_Fr > lagrangeCoeffs = obj.LagrangeCoeffs( participatingNodes );

    libff::alt_bn128_G2 key =  libff::alt_bn128_G2::zero();
    size_t i = 0;
    for (auto&& item: koefs_pkeys_map ){
        key = key + lagrangeCoeffs.at(i) * (*item.second->getPublicKey()) ;
        i++;
   }

   return make_shared<BLSPublicKey>(key);
}