#include <threshold_encryption.h>
#include <tools/utils.h>
#include <fstream>
#include <iostream>

int main() {
    crypto::ThresholdUtils::initCurve();
    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    std::ofstream secretKeyFile;
    secretKeyFile.open( "secret_key.txt" );
    secretKeyFile << crypto::ThresholdUtils::fieldElementToString( secret_key );

    auto vector_coordinates = crypto::ThresholdUtils::G2ToString( public_key, 16 );

    std::string result = "";
    for ( auto& coord : vector_coordinates ) {
        while (coord.size() < 64) {
            coord = "0" + coord;
        }
        result += coord;
    }

    std::ofstream publicKeyFile;
    publicKeyFile.open( "bls_public_key.txt" );
    publicKeyFile << result;

    libff::alt_bn128_Fr message_number = libff::alt_bn128_Fr::random_element();
    std::string message = crypto::ThresholdUtils::fieldElementToString( message_number, 16 );

    std::ofstream messageFile;
    messageFile.open( "message.txt" );
    messageFile << message;

    return 0;
}