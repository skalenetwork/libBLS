#include <threshold_encryption/ThresholdEncryption.h>
#include <tools/utils.h>
#include <iostream>

// use the same algorithm that is used in JS part
int main( int argc, char* argv[] ) {
    if ( argc != 3 ) {
        std::cout << "Wrong number of arguments\n" << argc << '\n';
        return 1;
    }

    std::string common_public_str = argv[1];
    std::string message = argv[2];

    libBLS::ThresholdUtils::initCurve();

    // convert from char into vec of bytes
    std::vector< uint8_t > messageBytes =
        libBLS::ThresholdUtils::hexCStringToBytes( message.c_str() );

    // build public key
    libBLS::TEPublicKey commonPublic( common_public_str );

    // encrypt message
    libBLS::Ciphertext cipheredMessage =
        libBLS::ThresholdEncryption::encrypt( messageBytes, commonPublic );
    std::vector< uint8_t > cipheredMessageBytes = cipheredMessage.toBytes();

    std::string cipheredMessageStr =
        libBLS::ThresholdUtils::bytesToHexString( cipheredMessageBytes );

    std::cout << cipheredMessageStr;

    return 0;
}
