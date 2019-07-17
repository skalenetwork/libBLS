
using namespace std;


#include "BLSPrivateKey.h"
#include "BLSSignature.h"
#include "BLSSignature.h"
#include "BLSSigShare.h"
#include "BLSutils.cpp"

BLSPrivateKey::BLSPrivateKey(const string &_key, size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    privateKey = make_shared<libff::alt_bn128_Fr>(_key.c_str());
    if (*privateKey == libff::alt_bn128_Fr::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Secret key share is equal to zero or corrupt"));
    }
}

BLSPrivateKey::BLSPrivateKey(const std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> skeys,
                             std::shared_ptr<std::vector<size_t >> koefs,
                             size_t _requiredSigners, size_t _totalSigners) :
        requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    privateKey = std::make_shared<libff::alt_bn128_Fr>(libff::alt_bn128_Fr::zero());
    signatures::Bls obj = signatures::Bls(_requiredSigners, _totalSigners);
    std::vector lagrange_koefs = obj.LagrangeCoeffs(*koefs);
    for (size_t i = 0; i < requiredSigners; i++) {
        libff::alt_bn128_Fr skey = *skeys->at(i)->getPrivateKey();
        *privateKey = *privateKey + lagrange_koefs.at(i) * skey;
    }

    if (*privateKey == libff::alt_bn128_Fr::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Secret key share is equal to zero or corrupt"));
    }
}

std::shared_ptr<libff::alt_bn128_Fr> BLSPrivateKey::getPrivateKey() const {
    return privateKey;
}

std::shared_ptr<std::string> BLSPrivateKey::toString() {
    if (!privateKey)
        BOOST_THROW_EXCEPTION(runtime_error("Secret key share is null"));
    if (*privateKey == libff::alt_bn128_Fr::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Secret key share is equal to zero or corrupt"));
    }
    std::shared_ptr<std::string> key_str = std::make_shared<std::string>(ConvertToString(*privateKey));

    if (key_str->empty())
        BOOST_THROW_EXCEPTION(runtime_error("Secret key share string is empty"));
    return key_str;
}
