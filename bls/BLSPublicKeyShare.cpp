
#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSignature.h"
#include "bls.h"

using namespace std;

BLSPublicKeyShare::BLSPublicKeyShare( const string& k1, const string& k2, const string& k3, const string& k4,
                                      size_t _totalSigners, size_t _requiredSigners )
        :  requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSSignature::checkSigners( _requiredSigners,_totalSigners);


    publicKey = make_shared<libff::alt_bn128_G2>();

    publicKey->X.c0 = libff::alt_bn128_Fq(k1.c_str());
    publicKey->X.c1 = libff::alt_bn128_Fq(k2.c_str());
    publicKey->Y.c0 = libff::alt_bn128_Fq(k3.c_str());
    publicKey->Y.c1 = libff::alt_bn128_Fq(k4.c_str());
    publicKey->Z.c0 = libff::alt_bn128_Fq::one();
    publicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if (publicKey->X.c0 == libff::alt_bn128_Fq::zero() ||
        publicKey->X.c1 == libff::alt_bn128_Fq::zero() ||
        publicKey->Y.c0 == libff::alt_bn128_Fq::zero() ||
        publicKey->Y.c1 == libff::alt_bn128_Fq::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Public Key is equal to zero or corrupt"));
    }

}

BLSPublicKeyShare::BLSPublicKeyShare(  const libff::alt_bn128_Fr _skey,
                    size_t _totalSigners, size_t _requiredSigners )
        : requiredSigners( _requiredSigners ),  totalSigners( _totalSigners ) {

    if ( _skey.is_zero()){
        BOOST_THROW_EXCEPTION( runtime_error( "Secret Key is equal to zero or corrupt" ) );
    }
    publicKey = make_shared <libff::alt_bn128_G2 > (_skey * libff::alt_bn128_G2::one());
}

BLSPublicKeyShare::BLSPublicKeyShare(  const libff::alt_bn128_G2 pkey,
                                       size_t _totalSigners, size_t _requiredSigners )
        : totalSigners( _totalSigners ), requiredSigners( _requiredSigners ) {

    publicKey = make_shared <libff::alt_bn128_G2 > (pkey);
}

std::shared_ptr< libff::alt_bn128_G2 >  BLSPublicKeyShare::getPublicKey() const {
    return publicKey;
}

bool BLSPublicKeyShare::VerifySig ( std::shared_ptr< std::string > _msg, std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners){
    std::shared_ptr< signatures::Bls > obj;
    BLSSignature::checkSigners(_requiredSigners, _totalSigners );
    if( _msg -> empty() || !_msg ){
        BOOST_THROW_EXCEPTION( runtime_error( "Message is empty or null" ) );
    }
    if ( !sign_ptr || sign_ptr->getSigShare()->is_zero()){
        BOOST_THROW_EXCEPTION(runtime_error("Sig share is equal to zero or corrupt"));
    }

    obj = std::make_shared< signatures::Bls >( signatures::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->Verification ( *_msg, *(sign_ptr->getSigShare()), *publicKey);
    return res;
}