/*
Copyright (C) 2018-2019 SKALE Labs

This file is part of libBLS.

libBLS is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libBLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with libBLS. If not, see <https://www.gnu.org/licenses/>.

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/

#include <threshold_encryption/TEBase.h>
#include <tools/utils.h>
#include "backends/algebra_types.hpp"

namespace libBLS {

std::atomic< bool > TEBase::isLibffInitialized{ false };

void TEBase::initializeIfNecessary() {
    bool expected = false;
    if ( isLibffInitialized.compare_exchange_strong( expected, true ) ) {
        // TODO - should not be needed - we should enforce curve initialization before any libBLS call
        algebra::initCurve();
    }
}

TEBase::TEBase( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    initializeIfNecessary();
}

size_t TEBase::getRequiredSigners() const {
    return requiredSigners;
}

size_t TEBase::getTotalSigners() const {
    return totalSigners;
}

}  // namespace libBLS