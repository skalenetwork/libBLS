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

    @file BLSSignature.cpp
    @author Stan Kladko
    @date 2019
*/


#include "BLSSignature.h"

using namespace std;

shared_ptr< libff::alt_bn128_G1 > BLSSignature::getSig() const {
    return sig;
}
BLSSignature::BLSSignature(
    const shared_ptr< libff::alt_bn128_G1 > sig, size_t _requiredSigners, size_t _totalSigners )
    : sig( sig ), requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    checkSigners( _requiredSigners, _totalSigners );
}

BLSSignature::BLSSignature(
    shared_ptr< string > _s, size_t _requiredSigners, size_t _totalSigners ) :
    requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {

    checkSigners( _requiredSigners, _totalSigners );

    if ( _s->size() > BLS_MAX_SIG_LEN ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Signature too long" ) );
    }

    auto position = _s->find( ":" );

    if ( position == string::npos ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Misformatted sig:" + *_s ) );
    }

    if ( position >= BLS_MAX_COMPONENT_LEN || _s->size() - position > BLS_MAX_COMPONENT_LEN ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Misformatted sig:" + *_s ) );
    }


    auto component1 = _s->substr( 0, position );
    auto component2 = _s->substr( position + 1 );


    for ( char& c : component1 ) {
        if ( !( c >= '0' && c <= '9' ) ) {
            BOOST_THROW_EXCEPTION( runtime_error(
                "Misformatted char:" + to_string( ( int ) c ) + " in component 1:" + component1 ) );
        }
    }


    for ( char& c : component2 ) {
        if ( !( c >= '0' && c <= '9' ) ) {
            BOOST_THROW_EXCEPTION( runtime_error(
                "Misformatted char:" + to_string( ( int ) c ) + " in component 2:" + component2 ) );
        }
    }


    libff::bigint< 4 > X( component1.c_str() );
    libff::bigint< 4 > Y( component2.c_str() );
    libff::bigint< 4 > Z( "1" );

    sig = make_shared< libff::alt_bn128_G1 >( X, Y, Z );
}
shared_ptr< string > BLSSignature::toString() {
    char str[512];


    gmp_sprintf( str, "%Nd:%Nd", sig->X.as_bigint().data, libff::alt_bn128_Fq::num_limbs,
        sig->Y.as_bigint().data, libff::alt_bn128_Fq::num_limbs );

    return make_shared< string >( str );
}
void BLSSignature::checkSigners( size_t _requiredSigners, size_t _totalSigners ) {
    if ( _requiredSigners > _totalSigners ) {
        BOOST_THROW_EXCEPTION( runtime_error( "_requiredSigners > _totalSigners" ) );
    }


    if ( _totalSigners == 0 ) {
        BOOST_THROW_EXCEPTION( runtime_error( "_totalSigners == 0" ) );
    }
}


size_t BLSSignature::getTotalSigners() const {
    return totalSigners;
}
size_t BLSSignature::getRequiredSigners() const {
    return requiredSigners;
}
