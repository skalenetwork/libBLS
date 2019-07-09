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

    @file BLSSigShare.cpp
    @author Stan Kladko
    @date 2019
*/

#include <stdlib.h>
#include <string>

using namespace std;


#include "BLSSigShare.h"
#include "BLSSignature.h"


shared_ptr< libff::alt_bn128_G1 > BLSSigShare::getSigShare() const {
    return sigShare;
}
size_t BLSSigShare::getSignerIndex() const {
    return signerIndex;
}

shared_ptr< string > BLSSigShare::toString() {
    char str[512];

    gmp_sprintf( str, "%Nd:%Nd", sigShare->X.as_bigint().data, libff::alt_bn128_Fq::num_limbs,
        sigShare->Y.as_bigint().data, libff::alt_bn128_Fq::num_limbs );

    return make_shared< string >( str );
}

BLSSigShare::BLSSigShare( shared_ptr< string > _sigShare, size_t signerIndex, size_t _totalSigners,
    size_t _requiredSigners )
    : signerIndex( signerIndex ),
      totalSigners( _totalSigners ),
      requiredSigners( _requiredSigners ) {
    BLSSignature::checkSigners( totalSigners, requiredSigners );

    if ( signerIndex == 0 ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Zero signer index" ) );
    }

    if ( !_sigShare ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Null _sigShare" ) );
    }


    if ( _sigShare->size() < 10 ) {
        BOOST_THROW_EXCEPTION(
            runtime_error( "Signature too short:" + to_string( _sigShare->size() ) ) );
    }

    if ( _sigShare->size() > BLS_MAX_SIG_LEN ) {
        BOOST_THROW_EXCEPTION(
            runtime_error( "Signature too long:" + to_string( _sigShare->size() ) ) );
    }

    auto position = _sigShare->find( ":" );

    if ( position == string::npos ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Misformatted sig:" + *_sigShare ) );
    }

    if ( position >= BLS_MAX_COMPONENT_LEN ||
         _sigShare->size() - position > BLS_MAX_COMPONENT_LEN ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Misformatted sig:" + *_sigShare ) );
    }


    auto component1 = _sigShare->substr( 0, position );
    auto component2 = _sigShare->substr( position + 1 );


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

    sigShare = make_shared< libff::alt_bn128_G1 >( X, Y, Z );
}
BLSSigShare::BLSSigShare( const shared_ptr< libff::alt_bn128_G1 >& _sigShare, size_t _signerIndex,
    size_t _totalSigners, size_t _requiredSigners )
    : sigShare( _sigShare ),
      signerIndex( _signerIndex ),
      totalSigners( _totalSigners ),
      requiredSigners( _requiredSigners ) {

    BLSSignature::checkSigners( totalSigners, requiredSigners );


    if ( _signerIndex == 0 ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Zero signer index" ) );
    }

    if ( !_sigShare ) {
        BOOST_THROW_EXCEPTION( runtime_error( "Null _s" ) );
    }
}
size_t BLSSigShare::getTotalSigners() const {
    return totalSigners;
}
size_t BLSSigShare::getRequiredSigners() const {
    return requiredSigners;
}
