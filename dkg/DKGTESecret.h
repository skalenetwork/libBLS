//
// Created by stan on 16.08.19.
//

#ifndef LIBBLS_DKGTESECRET_H
#define LIBBLS_DKGTESECRET_H

#include <threshold_encryption/threshold_encryption.h>

class DKGTESecret {
 private:
    size_t requiredSigners;
    size_t totalSigners;
    std::vector<encryption::element_wrapper> poly;
 public:
    DKGTESecret(size_t _requiredSigners, size_t _totalSigners);
    std::vector <encryption::element_wrapper> setPoly(std::vector <encryption::element_wrapper> _poly);
    std::vector <encryption::element_wrapper> getDKGTESecretShares();
    std::vector <encryption::element_wrapper> getDKGTEPublicShares();
    encryption::element_wrapper getValueAt0();
};


#endif //LIBBLS_DKGTESECRET_H
