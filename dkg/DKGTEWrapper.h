//
// Created by stan on 15.08.19.
//

#ifndef LIBBLS_DKGTEWRAPPER_H
#define LIBBLS_DKGTEWRAPPER_H

#include <dkg/dkg_te.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <dkg/DKGTESecret.h>

class DKGTEWrapper {

private:
    size_t requiredSigners;
    size_t totalSigners;

    std::shared_ptr<DKGTESecret> dkg_secret_ptr = NULL;

 public:
    DKGTEWrapper(size_t _requiredSigners, size_t _totalSigners);

    bool VerifyDKGShare( size_t signerIndex, const encryption::element_wrapper& share,
                 const std::vector<encryption::element_wrapper>& verification_vector);

    void setDKGSecret(std::shared_ptr<std::vector< encryption::element_wrapper>> _poly_ptr);

    std::shared_ptr < std::vector < encryption::element_wrapper>> createDKGSecretShares();

    std::shared_ptr < std::vector <encryption::element_wrapper>> createDKGPublicShares();

    TEPrivateKeyShare CreateTEPrivateKeyShare( size_t signerIndex_, std::shared_ptr<std::vector<encryption::element_wrapper>> secret_shares_ptr);

    encryption::element_wrapper getValueAt0();
};


#endif //LIBBLS_DKGTEWRAPPER_H
