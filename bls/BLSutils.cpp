
#include <memory>
#include <iostream>
#include <string>


#include "bls.h"
#include "BLSPrivateKeyShare.h"
#include "BLSSignature.h"
#include "BLSPublicKey.h"
#include "BLSPrivateKey.h"


template<class T>
std::string ConvertToString(T field_elem) {
    mpz_t t;
    mpz_init(t);

    field_elem.as_bigint().to_mpz(t);

    char * tmp = mpz_get_str(NULL, 10, t);
    mpz_clear(t);

    std::string output = tmp;

    return output;
}

/*BLSPrivateKey SKeyRecovery (std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare>>> sharedSkeys,  const std::vector<libff::alt_bn128_Fr>& coeffs,
                                 size_t _requiredSigners, size_t _totalSigners){
    libff::alt_bn128_Fr common_skey = libff::alt_bn128_Fr::zero();
    for (size_t i = 0; i < (*sharedSkeys).size(); i++ ){
        common_skey =  *sharedSkeys->at(i)->getPrivateKey()  * coeffs[i];
    }
    BLSPrivateKey ptr_common_skey( ConvertToString(common_skey), _requiredSigners, _totalSigners);
    return ptr_common_skey;
}*/

/*bool VerifySig ( std::shared_ptr< std::string > _msg, std::shared_ptr< BLSSignature > sign_ptr, std::shared_ptr <BLSPublicKey> pkey_ptr,
                 size_t _requiredSigners, size_t _totalSigners){
    std::shared_ptr< signatures::Bls > obj;

    obj = std::make_shared< signatures::Bls >( signatures::Bls( _requiredSigners, _totalSigners ) );


    return obj->Verification ( *_msg, *(sign_ptr->getSig()), *(pkey_ptr->getLibffPublicKey()));
}*/


