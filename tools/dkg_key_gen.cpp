/*
    Copyright (C) 2018-2019 SKALE Labs

    This file is part of libBLS.

    libBLS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libBLS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libBLS.  If not, see <http://www.gnu.org/licenses/>.

    @file dkg_key_gen.cpp
    @author Oleh Nikolaiev
    @date 2019
*/


#include <dkg/dkg.h>

#include <fstream>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#define EXPAND_AS_STR(x) __EXPAND_AS_STR__(x)
#define __EXPAND_AS_STR__(x) #x

static bool g_b_verbose_mode = false;

template<class T>
std::string ConvertToString(T field_elem) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char * tmp = mpz_get_str(NULL, 10, t);
  mpz_clear(t);

  std::string output = tmp;

  return output;
}

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

    // we will skip here a verification process

    for (size_t i = 0; i < n; ++i) {
      for (size_t j = i; j < n; ++j) {
        secret_key_contribution[i][j] = secret_key_contribution[j][i];
      }
    }

    std::vector<libff::alt_bn128_Fr> secret_key(n);
    std::vector<libff::alt_bn128_G2> public_keys(n);
    libff::alt_bn128_G2 common_public_key = libff::alt_bn128_G2::zero();
    for (size_t i = 0; i < n; ++i) {
      secret_key[i] = dkg_instance.SecretKeyShareCreate(secret_key_contribution[i]);
      public_keys[i] = polynomial[i][0] * libff::alt_bn128_G2::one();
      common_public_key = common_public_key + public_keys[i];
    }

    for (size_t i = 0; i < n; ++i) {
      nlohmann::json secret_key_file;

      secret_key_file["secret_key"] = ConvertToString<libff::alt_bn128_Fr>(secret_key[i]);

      std::string str_file_name = "secret_key" + std::to_string(i) + ".json";
      std::ofstream out(str_file_name.c_str());
      out << secret_key_file.dump(4) << "\n";

      if (g_b_verbose_mode)
        std::cout
          << str_file_name << " file:\n"
          << secret_key_file.dump(4) << "\n\n";
    }

    nlohmann::json public_key_json;
    public_key_json["public_key"]["X"]["c0"] =
                                        ConvertToString<libff::alt_bn128_Fq>(common_public_key.X.c0);
    public_key_json["public_key"]["X"]["c1"] =
                                        ConvertToString<libff::alt_bn128_Fq>(common_public_key.X.c1);
    public_key_json["public_key"]["Y"]["c0"] =
                                        ConvertToString<libff::alt_bn128_Fq>(common_public_key.Y.c0);
    public_key_json["public_key"]["Y"]["c1"] =
                                        ConvertToString<libff::alt_bn128_Fq>(common_public_key.Y.c1);
    public_key_json["public_key"]["Z"]["c0"] =
                                        ConvertToString<libff::alt_bn128_Fq>(common_public_key.Z.c0);
    public_key_json["public_key"]["Z"]["c1"] =
                                        ConvertToString<libff::alt_bn128_Fq>(common_public_key.Z.c1);

    std::ofstream outfile_pk("public_key.json");
    outfile_pk << public_key_json.dump(4) << "\n";
  } else {
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance.GeneratePolynomial();

    std::vector<libff::alt_bn128_Fr> secret_key_contribution = dkg_instance.SecretKeyContribution(polynomial);

    std::vector<libff::alt_bn128_G2> verification_vector = dkg_instance.VerificationVector(polynomial);

    nlohmann::json data;
    data["idx"] = std::to_string(idx);

    for (size_t i = 0; i < n; ++i) {
      data["secret_key_contribution"][std::to_string(i)] = ConvertToString<libff::alt_bn128_Fr>(secret_key_contribution[i]);
    }

    for (size_t i = 0; i < t; ++i) {
      data["verification_vector"][std::to_string(i)]["X"]["c0"] = 
                                ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].X.c0);
      data["verification_vector"][std::to_string(i)]["X"]["c1"] =
                                ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].X.c1);
      data["verification_vector"][std::to_string(i)]["Y"]["c0"] =
                                ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Y.c0);
      data["verification_vector"][std::to_string(i)]["Y"]["c1"] =
                                ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Y.c1);
      data["verification_vector"][std::to_string(i)]["Z"]["c0"] =
                                ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Z.c0);
      data["verification_vector"][std::to_string(i)]["Z"]["c1"] =
                                ConvertToString<libff::alt_bn128_Fq>(verification_vector[i].Z.c1);
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
      if( g_b_verbose_mode )
        std::cout << "j = " << j << '\n';
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
