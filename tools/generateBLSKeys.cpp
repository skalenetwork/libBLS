/*
Copyright (C) 2021- SKALE Labs

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

@file generateBLSKeys.cpp
@author Oleh Nikolaiev
@date 2021
*/

#include <threshold_encryption.h>
#include <tools/utils.h>
#include <fstream>
#include <iostream>

using namespace libBLS;

int main() {
    ThresholdUtils::initCurve();
    algebra::FrScalar secret_key = algebra::FrScalar::random();
    algebra::G2Point public_key = secret_key * algebra::G2Point::generator();

    std::ofstream secretKeyFile;
    secretKeyFile.open( "secret_key.txt" );
    secretKeyFile << secret_key.toString( libBLS::Base::DEC );

    auto vector_coordinates = public_key.toStringArray( Base::HEXA );

    std::string result = "";
    for ( auto& coord : vector_coordinates ) {
        while ( coord.size() < 64 ) {
            coord = "0" + coord;
        }
        result += coord;
    }

    std::ofstream publicKeyFile;
    publicKeyFile.open( "bls_public_key.txt" );
    publicKeyFile << result;

    std::string message = "0";
    while ( message.size() % 2 != 0 ) {
        algebra::FrScalar message_number = algebra::FrScalar::random();
        message = message_number.toString( Base::DEC );
    }

    std::ofstream messageFile;
    messageFile.open( "message.txt" );
    messageFile << message;

    return 0;
}
