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

    @file BLSPublicKey.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SKALED_BLSPUBLICKEY_H
#define SKALED_BLSPUBLICKEY_H

#include <map>

#include "bls.h"
#include "BLSPublicKeyShare.h"

namespace libff {
class alt_bn128_G2;
}


class BLSPublicKey {
    std::shared_ptr< libff::alt_bn128_G2 > libffPublicKey;


    size_t totalSigners;
    size_t requiredSigners;

public:
    BLSPublicKey( const std::string& k1, const std::string& k2, const std::string& k3, const std::string& k4,
        size_t _totalSigners, size_t _requiredSigners );
    BLSPublicKey(  const libff::alt_bn128_Fr& skey,
                        size_t _totalSigners, size_t _requiredSigners );

    BLSPublicKey(const  libff::alt_bn128_G2 );

    std::shared_ptr< libff::alt_bn128_G2 > getLibffPublicKey() const;
    size_t getTotalSigners() const;
    size_t getRequiredSigners() const;


    bool VerifySig ( std::shared_ptr< std::string > _msg, std::shared_ptr< BLSSignature > sign_ptr,
                     size_t _requiredSigners, size_t _totalSigners);

    std::shared_ptr <BLSPublicKey> gluePublicKey (std::map<size_t, std::shared_ptr<BLSPublicKeyShare> >);

};


#endif  // SKALED_BLSPUBLICKEY_H
