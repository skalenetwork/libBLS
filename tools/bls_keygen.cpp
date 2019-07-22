/*
  Copyright (C) 2018-2019 SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file dkg_key_gen.cpp
  @author Sveta Rogova
  @date 2019
*/

#include <third_party/json.hpp>

#include "bls/BLSPrivateKeyShare.h"
#include "bls/BLSPublicKeyShare.h"
#include "bls/BLSPublicKey.h"

#include "bls/BLSPrivateKey.h"

#include <fstream>


void keys_to_json(std::shared_ptr<BLSPrivateKeyShare> skey_ptr, size_t num_signed, size_t num_all, size_t num) {
    nlohmann::json keys_json;
    keys_json["insecureBLSPrivateKey"] = *skey_ptr->toString();
    BLSPublicKeyShare pkey(*skey_ptr->getPrivateKey(), num_signed, num_all);
    std::shared_ptr<std::vector<std::string> > pkey_ptr = pkey.toString();
    std::string pkey_name = "insecureBLSPublicKey";
    for (size_t i = 1; i < 5; i++) {
        keys_json[pkey_name + std::to_string(i)] = pkey_ptr->at(i - 1);
    }

    std::ofstream outfile("key" + std::to_string(num) + ".json");
    outfile << std::setw(4) << keys_json << std::endl;
    outfile.close();
}

void common_pkey_to_json(std::shared_ptr<BLSPublicKey> common_pkey_ptr,
                               size_t num_signed, size_t num_all) {
    nlohmann::json keys_json;
    std::string pkey_name = "insecureCommonBLSPublicKey";
    std::shared_ptr<std::vector<std::string> > common_pkey_str = common_pkey_ptr->toString();
    for (size_t i = 1; i < 5; i++) {
        keys_json[pkey_name + std::to_string(i)] = common_pkey_str->at(i - 1);
    }

    std::ofstream outfile("publickey.json");
    outfile << std::setw(4) << keys_json << std::endl;
    outfile.close();
}

int main(int argc, const char *argv[]) {
    int num_signed, num_all;
    try {
        if (argc != 3)
            throw std::runtime_error("Wrong number of arguments");
        num_signed = std::stoi(argv[1]);
        num_all = std::stoi(argv[2]);
        std::shared_ptr<std::pair<std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>>, std::shared_ptr<BLSPublicKey> > > keys =  BLSPrivateKeyShare::generateSampleKeys(
                num_signed, num_all);
        //std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> skeys = BLSPrivateKeyShare::generateSampleKeys(
                //num_signed, num_all)->first;
        for (size_t i = 0; i < num_all; i++) {
            keys_to_json(keys->first->at(i), num_signed, num_all, i + 1);
        }
        common_pkey_to_json(keys->second, num_signed, num_all);

        return 0;
    } catch (std::exception &ex) {
        std::string str_what = ex.what();
        if (str_what.empty())
            str_what = "exception without description";
        std::cerr << "exception: " << str_what << "\n";
    } catch (...) {
        std::cerr << "unknown exception\n";
    }
    return 1;
}