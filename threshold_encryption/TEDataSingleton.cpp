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
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file TEPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#include "TEDataSingleton.h"
#include <stdexcept>

TEDataSingleton::TEDataSingleton() {
    char aparam[] =
            "type a\n"
            "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
            "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
            "r 730750818665451621361119245571504901405976559617\n"
            "exp2 159\n"
            "exp1 107\n"
            "sign1 1\n"
            "sign0 1\n";

    pairing_init_set_str(pairing_, aparam);

    element_init_G1(generator_, pairing_);
    element_random(generator_);
    while (element_is0(generator_)){
        element_random(generator_);
    }

}

void TEDataSingleton::checkSigners(size_t _requiredSigners, size_t _totalSigners ){

    if ( _requiredSigners > _totalSigners ) {
        throw  std::runtime_error( "_requiredSigners > _totalSigners" ) ;
    }

    if ( _totalSigners == 0 ) {
        throw  std::runtime_error( "_totalSigners == 0" ) ;
    }

    if ( _requiredSigners == 0 ) {
        throw  std::runtime_error( "_requiredSigners == 0" ) ;
    }
}

TEDataSingleton::~TEDataSingleton() {
    element_clear(generator_);
    pairing_clear(pairing_);
}