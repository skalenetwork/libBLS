#include <threshold_encryption.h>
#include <tools/utils.h>

extern "C" {

const char* encryptMessage( const char* data, const char* key ) {
    crypto::ThresholdUtils::initCurve();
    auto ciphertext_string = crypto::TE::encryptMessage( data, key );

    return std::move( ciphertext_string.c_str() );
}

}