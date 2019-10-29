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
  @author Oleh Nikolaiev
  @date 2019
*/


#include <dkg/dkg.h>

#include <fstream>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPrivateKey.h>
#include <bls/BLSutils.h>


#define EXPAND_AS_STR(x) __EXPAND_AS_STR__(x)
#define __EXPAND_AS_STR__(x) #x


void KeysToJson(std::shared_ptr<BLSPrivateKeyShare> skey_ptr, size_t num_signed, size_t num_all, size_t num) {
  nlohmann::json keys_json;
  keys_json["insecureBLSPrivateKey"] = *skey_ptr->toString();
  BLSPublicKeyShare pkey(*skey_ptr->getPrivateKey(), num_signed, num_all);
  std::shared_ptr<std::vector<std::string> > pkey_ptr = pkey.toString();
  std::string pkey_name = "insecureBLSPublicKey";
  for (size_t i = 0; i < 4; i++) {
    keys_json[pkey_name + std::to_string(i)] = pkey_ptr->at(i);
  }

  std::ofstream outfile("BLS_keys" + std::to_string(num) + ".json");
  outfile << std::setw(4) << keys_json << std::endl;
  outfile.close();
}

void CommonPkeyToJson(std::shared_ptr<BLSPublicKey> common_pkey_ptr,
 size_t num_signed, size_t num_all) {
  nlohmann::json keys_json;
  std::string pkey_name = "insecureCommonBLSPublicKey";
  std::shared_ptr<std::vector<std::string> > common_pkey_str = common_pkey_ptr->toString();
  for (size_t i = 0; i < 4; ++i) {
    keys_json[pkey_name + std::to_string(i)] = common_pkey_str->at(i);
  }

  std::ofstream outfile("common_public_key.json");
  outfile << std::setw(4) << keys_json << std::endl;
  outfile.close();
}

static bool g_b_verbose_mode = false;

void KeyGeneration(const size_t t, const size_t n, bool generate_all = true, int idx = -1) {
  signatures::Dkg dkg_instance =  signatures::Dkg(t, n);
  
  if (generate_all) {
    std::vector<std::vector<libff::alt_bn128_Fr>> polynomial(n);

    for (auto& pol : polynomial) {
      pol = dkg_instance.GeneratePolynomial();
    }

    std::vector<std::vector<libff::alt_bn128_Fr>> secret_key_contribution(n);
    for (size_t i = 0; i < n; ++i) {
      secret_key_contribution[i] = dkg_instance.SecretKeyContribution(polynomial[i]);
    }

    std::vector<std::vector<libff::alt_bn128_G2>> verification_vector(n);
    for (size_t i = 0; i < n; ++i) {
      verification_vector[i] = dkg_instance.VerificationVector(polynomial[i]);
    }

    for (size_t i = 0; i < n; ++i) {
      for (size_t j = i; j < n; ++j) {
        std::swap(secret_key_contribution[j][i], secret_key_contribution[i][j]);
      }
    }

    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < n; ++j) {
        if (!dkg_instance.Verification(i, secret_key_contribution[i][j], verification_vector[j])) {
          throw std::runtime_error("not verified");
        }
      }
    }

    std::vector<std::shared_ptr<BLSPrivateKeyShare>> skeys;
    libff::alt_bn128_G2 common_public_key = libff::alt_bn128_G2::zero();
    for (size_t i = 0; i < n; ++i) {
      common_public_key = common_public_key + polynomial[i][0] * libff::alt_bn128_G2::one();
      BLSPrivateKeyShare cur_skey(dkg_instance.SecretKeyShareCreate(secret_key_contribution[i]), t, n);
      skeys.push_back(std::make_shared<BLSPrivateKeyShare>(cur_skey));
    }

    CommonPkeyToJson( std::make_shared<BLSPublicKey>(common_public_key, t, n), t , n );

    for (size_t i = 0; i < n; ++i) {
      KeysToJson(skeys.at(i), t, n , i);
    }

  } else {
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance.GeneratePolynomial();

    std::vector<libff::alt_bn128_Fr> secret_key_contribution = dkg_instance.SecretKeyContribution(polynomial);

    std::vector<libff::alt_bn128_G2> verification_vector = dkg_instance.VerificationVector(polynomial);

    nlohmann::json data;
    data["idx"] = std::to_string(idx);

    for (size_t i = 0; i < n; ++i) {
      data["secret_key_contribution"][std::to_string(i)] = BLSutils::ConvertToString<libff::alt_bn128_Fr>(secret_key_contribution[i]);
    }


    for (size_t i = 0; i < t; ++i) {
      data["verification_vector"][std::to_string(i)]["X"]["c0"] = 
      BLSutils::ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].X.c0);
      data["verification_vector"][std::to_string(i)]["X"]["c1"] =
      BLSutils::ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].X.c1);
      data["verification_vector"][std::to_string(i)]["Y"]["c0"] =
      BLSutils::ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Y.c0);
      data["verification_vector"][std::to_string(i)]["Y"]["c1"] =
      BLSutils::ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Y.c1);
      data["verification_vector"][std::to_string(i)]["Z"]["c0"] =
      BLSutils::ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Z.c0);
      data["verification_vector"][std::to_string(i)]["Z"]["c1"] =
      BLSutils::ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Z.c1);
    }

    std::ofstream outfile("data_for_" + std::to_string(idx) + "-th_participant.json");
    outfile << data.dump(4) << "\n\n";
  }
}

int main(int argc, const char *argv[]) {
  try {
    boost::program_options::options_description desc("Options");
    desc.add_options()
    ("help", "Show this help screen")
    ("version", "Show version number")
    ("t", boost::program_options::value<size_t>(), "Threshold")
    ("n", boost::program_options::value<size_t>(), "Number of participants")
    ("j", boost::program_options::value<int>(), "Index of participant to generate data to create secret key; if not specified then all participants")
    ("v", "Verbose mode (optional)");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc <= 1) {
      std::cout
      << "Distributed key generator, version " << EXPAND_AS_STR(BLS_VERSION) << '\n'
      << "Usage:\n"
      << "   " << argv[0] << " --t <threshold> --n <num_participants> [--j <participant>] [--v]" << '\n'
      << desc
      << "Output is set of secret_key<j>.json files where 0 <= j < n or generated data to start key creation process.\n";
      return 0;
    }
    if (vm.count("version")) {
      std::cout
      << EXPAND_AS_STR(BLS_VERSION) << '\n';
      return 0;
    }

    if (vm.count("t") == 0)
      throw std::runtime_error("--t is missing (see --help)");
    if (vm.count("n") == 0)
      throw std::runtime_error("--n is missing (see --help)");

    int j = -1;
    if (vm.count("j")) {
      j = vm["j"].as<int>();
      if(g_b_verbose_mode) {
        std::cout << "j = " << j << '\n';
      }
    }

    if (vm.count("v"))
      g_b_verbose_mode = true;

    size_t t = vm["t"].as<size_t>();
    size_t n = vm["n"].as<size_t>();
    if (g_b_verbose_mode)
      std::cout
    << "t = " << t << '\n'
    << "n = " << n << '\n'
    << '\n';

    if (j < 0) {
      KeyGeneration(t, n);
    } else {
      KeyGeneration(t, n, false, j);
    }
    return 0;  // success
  } catch (std::exception& ex) {
    std::string str_what = ex.what();
    if (str_what.empty())
      str_what = "exception without description";
    std::cerr << "exception: " << str_what << "\n";
  } catch (...) {
    std::cerr << "unknown exception\n";
  }
  return 1;
}
