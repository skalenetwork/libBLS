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
std::string encryptMessage(const std::string& message, const std::string& key) {
    crypto::ThresholdUtils::initCurve();
    auto ciphertext_string = crypto::TE::encryptMessage( message, key );

    // std::cout << ciphertext_string << '\n';

    return ciphertext_string;
}
}