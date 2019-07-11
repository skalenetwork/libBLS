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

    @file BLSSigShare.h
    @author Stan Kladko
    @date 2019
*/
#ifndef SKALED_BLSSIGSHARE_H
#define SKALED_BLSSIGSHARE_H


#include <stdlib.h>
#include <string>
#include "bls.h"

namespace libff {
class alt_bn128_G1;
}

class BLSSigShare {

private:
    std::shared_ptr< libff::alt_bn128_G1 > sigShare;
    size_t signerIndex;
    size_t totalSigners;
    size_t requiredSigners;

public:


    BLSSigShare( const std::shared_ptr< libff::alt_bn128_G1 >& sigShare, size_t signerIndex,
                 size_t _requiredSigners, size_t _totalSigners );

    BLSSigShare( std::shared_ptr< string > _sigShare, size_t signerIndex,
                 size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< libff::alt_bn128_G1 > getSigShare() const;

    size_t getSignerIndex() const;

    std::shared_ptr< std::string > toString();
    size_t getTotalSigners() const;
    size_t getRequiredSigners() const;
};


#endif  // SKALED_BLSSIGSHARE_H
