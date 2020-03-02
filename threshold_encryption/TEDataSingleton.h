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

#include <pbc/pbc.h>

#ifndef LIBBLS_TEBASEWRAPPER_H
#define LIBBLS_TEBASEWRAPPER_H


class TEDataSingleton {
private:
    TEDataSingleton();

public:
    pairing_t pairing_;
    element_t generator_;

    static TEDataSingleton& getData() {
        static TEDataSingleton data;
        return data;
    }

    static void checkSigners( size_t _requiredSigners, size_t _totalSigners );

    ~TEDataSingleton();
};


#endif  // LIBBLS_TEBASEWRAPPER_H
