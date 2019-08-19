//
// Created by stan on 19.08.19.
//

#ifndef LIBBLS_DKGBLSSECRET_H
#define LIBBLS_DKGBLSSECRET_H


class DKGBLSSecret {
private:
    size_t requiredSigners;
    size_t totalSigners;
    std::vector<libff::alt_bn128_Fr> poly;
public:
    DKGBLSSecret(size_t _requiredSigners, size_t _totalSigners);
    std::vector <libff::alt_bn128_Fr> setPoly(std::vector <libff::alt_bn128_Fr> _poly);
    std::vector <libff::alt_bn128_Fr> getDKGBLSSecretShares();
    std::vector <libff::alt_bn128_Fr> getDKGBLSPublicShares();
    libff::alt_bn128_Fr getValueAt0();
};


#endif //LIBBLS_DKGBLSSECRET_H
