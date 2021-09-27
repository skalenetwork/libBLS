#include <threshold_encryption.h>
#include <tools/utils.h>
#include <iostream>

int main() {
    crypto::ThresholdUtils::initCurve();
    crypto::TE te_instance = crypto::TE( 1, 1 );
    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::one();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto str = crypto::ThresholdUtils::G2ToString( public_key, 16 );
    std::string common_public_str = "";
    for ( auto& elem : str ) {
        while ( elem.size() < 64 ) {
            elem = "0" + elem;
        }
        common_public_str += elem;
    }
    auto ciphertext_string = te_instance.encryptMessage( message, common_public_str );

    // auto ciphertext_with_aes = te_instance.aesCiphertextFromString( ciphertext_string );

    // auto ciphertext = ciphertext_with_aes.first;
    // auto encrypted_message = ciphertext_with_aes.second;

    // libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key
    // );

    // assert( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    // std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    // shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    // std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    // std::string plaintext = ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    // std::cout << TE::encryptMessage(message, common_public_str) << '\n';
    // assert( plaintext == message );
    std::cout << ciphertext_string;
    return 0;
}