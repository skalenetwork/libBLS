#include <threshold_encryption.h>
#include <tools/utils.h>
#include <fstream>

int main() {
    std::ifstream encryptedDataFile, secretKeyFile;
    encryptedDataFile.open( "encrypted_data.txt" );
    secretKeyFile.open( "secret_key.txt" );

    std::string encryptedData;
    encryptedDataFile >> encryptedData;

    std::string secretKey;
    secretKeyFile >> secretKey;

    auto te_instance = crypto::TE( 1, 1 );

    auto ciphertext_with_aes = te_instance.aesCiphertextFromString( encryptedData );

    auto ciphertext = ciphertext_with_aes.first;
    auto encrypted_message = ciphertext_with_aes.second;

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr( secretKey.c_str() );
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    assert( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::string plaintext =
        crypto::ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    std::ifstream messageFile;
    messageFile.open( "message.txt" );
    std::string message;
    messageFile >> message;

    assert( message == plaintext );

    return 0;
}