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

    @file BLSPrivateKeyShare.h
    @author Stan Kladko
    @date 2019
*/
#ifndef SKALED_BLSPRIVATEKEYSHARE_H
#define SKALED_BLSPRIVATEKEYSHARE_H

#include <stdlib.h>
#include <string>

#include "bls.h"

class BLSSigShare;

namespace libff {
    class alt_bn128_fr;
}

class BLSPrivateKeyShare {
protected:
    std::shared_ptr< libff::alt_bn128_Fr > privateKey;
    size_t totalSigners;
    size_t requiredSigners;

public:
    BLSPrivateKeyShare( const std::string& _key, size_t _totalSigners, size_t _requiredSigners );
    std::shared_ptr< BLSSigShare > sign( std::shared_ptr< string > _msg, size_t _signerIndex );


    // generate a vector of correct _totalSigners private keys that work together

    //static shared_ptr< vector< shared_ptr< BLSPrivateKeyShare>>> generateSampleKeys(
    //    size_t _totalSigners, size_t _requiredSigners );


};


#endif  // SKALED_BLSPRIVATEKEYSHARE_H
