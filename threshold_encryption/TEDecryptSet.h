//
// Created by stan on 31.07.19.
//

#ifndef LIBBLS_TEDECRYPTSET_H
#define LIBBLS_TEDECRYPTSET_H

#include <map>
#include "threshold_encryption.h"

class TEDecryptSet {
    size_t requiredSigners;
    size_t totalSigners;

    std::map<size_t, std::shared_ptr< encryption::element_wrapper>> decrypts;

public:
    TEDecryptSet(size_t _requiredSigners, size_t _totalSigners);

    void addDecrypt ( size_t _signerIndex, std::shared_ptr< encryption::element_wrapper>& _el);

    std::string merge(const encryption::Ciphertext& ciphertext);
};


#endif //LIBBLS_TEDECRYPTSET_H
