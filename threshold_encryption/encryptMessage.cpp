#include <threshold_encryption.h>
#include <tools/utils.h>
// #include <iostream>

// int main( int argc, char* argv[] ) {
//     if ( argc != 3 ) {
//         // argv[0] is path to .js file
//         std::cout << "Wrong number of arguments\n" << argc << '\n';
//         return 1;
//     }

//     std::string message = argv[1];
//     std::string common_public_str = argv[2];

//     crypto::ThresholdUtils::initCurve();
//     auto ciphertext_string = crypto::TE::encryptMessage( message, common_public_str );

//     std::cout << "cipher " << ciphertext_string;
//     return 0;
// }
extern "C" {
const char* encryptMessage( const char* data, const char* key ) {
    crypto::ThresholdUtils::initCurve();
    auto ciphertext_string = crypto::TE::encryptMessage( data, key );

    return std::move( ciphertext_string.c_str() );
}
}