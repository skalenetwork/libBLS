
#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSignature.h"
#include "BLSutils.cpp"
#include "bls.h"

using namespace std;

BLSPublicKeyShare::BLSPublicKeyShare(const string &k1, const string &k2, const string &k3, const string &k4,
                                     size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);


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

BLSPublicKeyShare::BLSPublicKeyShare(const std::shared_ptr<std::vector<std::string> > pkey_str_vect,
                                     size_t _requiredSigners,
                                     size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {

    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    publicKey = make_shared<libff::alt_bn128_G2>();

    publicKey->X.c0 = libff::alt_bn128_Fq(pkey_str_vect->at(0).c_str());
    publicKey->X.c1 = libff::alt_bn128_Fq(pkey_str_vect->at(1).c_str());
    publicKey->Y.c0 = libff::alt_bn128_Fq(pkey_str_vect->at(2).c_str());
    publicKey->Y.c1 = libff::alt_bn128_Fq(pkey_str_vect->at(3).c_str());
    publicKey->Z.c0 = libff::alt_bn128_Fq::one();
    publicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if (publicKey->X.c0 == libff::alt_bn128_Fq::zero() ||
        publicKey->X.c1 == libff::alt_bn128_Fq::zero() ||
        publicKey->Y.c0 == libff::alt_bn128_Fq::zero() ||
        publicKey->Y.c1 == libff::alt_bn128_Fq::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Public Key is equal to zero or corrupt"));
    }
}

BLSPublicKeyShare::BLSPublicKeyShare(const libff::alt_bn128_Fr _skey,
                                     size_t _totalSigners, size_t _requiredSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {

    if (_skey.is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Secret Key is equal to zero or corrupt"));
    }
    publicKey = make_shared<libff::alt_bn128_G2>(_skey * libff::alt_bn128_G2::one());
}

std::shared_ptr<libff::alt_bn128_G2> BLSPublicKeyShare::getPublicKey() const {
    return publicKey;
}

std::shared_ptr<std::vector<std::string> > BLSPublicKeyShare::toString() {
    std::vector<std::string> pkey_str_vect;

    publicKey->to_affine_coordinates();

    pkey_str_vect.push_back(ConvertToString(publicKey->X.c0));
    pkey_str_vect.push_back(ConvertToString(publicKey->X.c1));
    pkey_str_vect.push_back(ConvertToString(publicKey->Y.c0));
    pkey_str_vect.push_back(ConvertToString(publicKey->Y.c1));

    return make_shared<vector<string>>(pkey_str_vect);
}

bool BLSPublicKeyShare::VerifySig(std::shared_ptr<std::string> _msg, std::shared_ptr<BLSSigShare> sign_ptr,
                                  size_t _requiredSigners, size_t _totalSigners) {
    std::shared_ptr<signatures::Bls> obj;
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    if (_msg->empty() || !_msg) {
        BOOST_THROW_EXCEPTION(runtime_error("Message is empty or null"));
    }
    if (!sign_ptr || sign_ptr->getSigShare()->is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Sig share is equal to zero or corrupt"));
    }

    obj = std::make_shared<signatures::Bls>(signatures::Bls(_requiredSigners, _totalSigners));

    bool res = obj->Verification(*_msg, *(sign_ptr->getSigShare()), *publicKey);
    return res;
}