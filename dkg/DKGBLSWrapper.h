//
// Created by stan on 16.08.19.
//

#ifndef LIBBLS_DKGBLSWRAPPER_H
#define LIBBLS_DKGBLSWRAPPER_H

#include <bls/BLSPrivateKeyShare.h>


class DKGBLSWrapper {
 private:
    size_t requiredSigners;
    size_t totalSigners;

    std::shared_ptr<DKGBLSSecret> dkg_secret_ptr = NULL;

  public:
    DKGBLSSWrapper(size_t _requiredSigners, size_t _totalSigners);

    bool VerifyDKGShare( size_t signerIndex, const elibff::alt_bn128_Fr& share,
                         const std::vector<libff::alt_bn128_G2>& verification_vector);

    void setDKGSecret(std::shared_ptr<std::vector< libff::alt_bn128_Fr>> _poly_ptr);

    std::shared_ptr < std::vector < libff::alt_bn128_Fr>> createDKGSecretShares();

    std::shared_ptr < std::vector <libff::alt_bn128_G2>> createDKGPublicShares();

    BLSPrivateKeyShare CreateBLSPrivateKeyShare(std::shared_ptr<std::vector<libff::alt_bn128_Fr>> secret_shares_ptr);

    libff::alt_bn128_Fr getValueAt0();
};


#endif //LIBBLS_DKGBLSWRAPPER_H
