//
// Created by stan on 31.07.19.
//

#include "TEDecryptSet.h"

TEDecryptSet::TEDecryptSet(size_t _requiredSigners, size_t _totalSigners) : requiredSigners(_requiredSigners),
                                                                            totalSigners(_totalSigners) {

}

void TEDecryptSet::addDecrypt (size_t _signerIndex, std::shared_ptr<encryption::element_wrapper>& _el ) {

    if ( decrypts.count( _signerIndex ) > 0 ) {
        throw std::runtime_error(
                "Already have this index:" + std::to_string(  _signerIndex ) ) ;
    }

    if ( !_el ) {
        throw std::runtime_error( "Null _element" );
    }

    decrypts[_signerIndex] = _el;
}

std::string TEDecryptSet::merge(const encryption::Ciphertext& ciphertext){
    if (decrypts.size() < requiredSigners)
        throw std::runtime_error("Not enough elements to decrypt message");

    encryption::TE te (requiredSigners, totalSigners);
    std::vector<std::pair<encryption::element_wrapper, size_t>> decrypted;
    for (auto&& item: decrypts){
        std::pair<encryption::element_wrapper, size_t> encr = std::make_pair(*item.second,item.first);
        decrypted.push_back(encr);
    }

    return  te.CombineShares(ciphertext, decrypted);
}