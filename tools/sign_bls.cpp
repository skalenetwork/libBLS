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

  @file sign_bls.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <bls/bls.h>
#include <bls/BLSutils.h>

#include <fstream>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#define EXPAND_AS_STR(x) __EXPAND_AS_STR__(x)
#define __EXPAND_AS_STR__(x) #x

static bool g_b_verbose_mode = false;


void Sign(const size_t t, const size_t n, std::istream& data_file,
          std::ostream& outfile, const std::string& key, bool sign_all = true, int idx = -1) {
  signatures::Bls bls_instance = signatures::Bls(t, n);

  std::vector<uint8_t> message_data;
  uint8_t n_byte;
  while (data_file >> n_byte) {
    message_data.push_back(n_byte);
  }

  std::string message(message_data.cbegin(), message_data.cend());
  std::string hash_str = cryptlite::sha256::hash_hex(message);
  std::array< uint8_t, 32>hash_bytes_arr;
  for (size_t i = 0; i < 32; i++ ){
    hash_bytes_arr.at(i) = static_cast<uint8_t>(hash_str[i]);
  }

  libff::alt_bn128_G1 hash = bls_instance.HashtoG1(std::make_shared<std::array< uint8_t, 32>>(hash_bytes_arr));

  nlohmann::json hash_json;
  hash_json["message"] = message;

  libff::alt_bn128_G1 common_signature;

  if (sign_all) {
    std::vector<libff::alt_bn128_Fr> secret_key(n);

    for (size_t i = 0; i < n; ++i) {
      nlohmann::json secret_key_file;

      std::ifstream infile(key + std::to_string(i) + ".json");
      infile >> secret_key_file;

      secret_key[i] = libff::alt_bn128_Fr(secret_key_file["insecureBLSPrivateKey"].get<std::string>().c_str());
    }

    std::vector<libff::alt_bn128_G1> signature_shares(n);
    for (size_t i = 0; i < n; ++i) {
      signature_shares[i] = bls_instance.Signing(hash, secret_key[i]);
    }

    std::vector<size_t> idx(t);
    for (size_t i = 0; i < t; ++i) {
      idx[i] = i + 1;
    }

    std::vector<libff::alt_bn128_Fr> lagrange_coeffs = bls_instance.LagrangeCoeffs(idx);

    common_signature = bls_instance.SignatureRecover(signature_shares, lagrange_coeffs);
  } else {
    libff::alt_bn128_Fr secret_key;

    nlohmann::json secret_key_file;

    std::ifstream infile(key + std::to_string(idx) + ".json");
    infile >> secret_key_file;

    secret_key = libff::alt_bn128_Fr(secret_key_file["insecureBLSPrivateKey"].get<std::string>().c_str());

    common_signature = bls_instance.Signing(hash, secret_key);
  }

  common_signature.to_affine_coordinates();

  nlohmann::json signature;
  if (idx >= 0) {
    signature["index"] = std::to_string(idx);
  }

  signature["signature"]["X"] = BLSutils::ConvertToString<libff::alt_bn128_Fq>(common_signature.X);
  signature["signature"]["Y"] = BLSutils::ConvertToString<libff::alt_bn128_Fq>(common_signature.Y);

  std::ofstream outfile_h("hash.json");
  outfile_h << hash_json.dump(4) << "\n";

  outfile << signature.dump(4) << "\n";
}

int main(int argc, const char *argv[]) {
  std::istream* p_in = &std::cin;
  std::ostream* p_out = &std::cout;
  int r = 1;
  try {
    boost::program_options::options_description desc("Options");
    desc.add_options()
    ("help", "Show this help screen")
    ("version", "Show version number")
    ("t", boost::program_options::value<size_t>(), "Threshold")
    ("n", boost::program_options::value<size_t>(), "Number of participants")
    ("input", boost::program_options::value<std::string>(),
      "Input file path with containing message to sign; if not specified then use standard input")
    ("j", boost::program_options::value<int>(),
      "Index of participant to sign; if not specified then all participants")
    ("key", boost::program_options::value<std::string>(),
      "Directory with secret keys which are BLS_keys<j>.json ")
    ("output", boost::program_options::value<std::string>(),
      "Output file path to save signature to; if not specified for common signature then use standard output;")
    ("v", "Verbose mode (optional)");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc <= 1) {
      std::cout
      << "BLS sign tool, version " << EXPAND_AS_STR(BLS_VERSION) << '\n'
      << "Usage:\n"
      << "   " << argv[0] << "--t <threshold> --n <num_participants> [--j <participant>] [--input <path>] [--output <path>] [--key <path>] [--v]" << '\n'
      << desc << '\n';
      return 0;
    }
    if (vm.count("version")) {
      std::cout << EXPAND_AS_STR(BLS_VERSION) << '\n';
      return 0;
    }

    if (vm.count("t") == 0) {
      throw std::runtime_error("--t is missing (see --help)");
    }

    if (vm.count("n") == 0) {
      throw std::runtime_error("--n is missing (see --help)");
    }

    if (vm.count("key") == 0) {
      throw std::runtime_error("--key is missing (see --help)");
    }

    if (vm.count("v")) {
      g_b_verbose_mode = true;
    }

    size_t t = vm["t"].as<size_t>();
    size_t n = vm["n"].as<size_t>();
    if (g_b_verbose_mode) {
      std::cout << "t = " << t << '\n' << "n = " << n << '\n' << '\n';
    }

    int j = -1;
    if (vm.count("j")) {
      j = vm["j"].as<int>();
      if (g_b_verbose_mode) {
        std::cout << "j = " << j << '\n';
      }
    }

    std::string key = vm["key"].as<std::string>();
    if (g_b_verbose_mode) {
      std::cout << "key = " << key << '\n';
    }

    if (vm.count("input")) {
      if (g_b_verbose_mode) {
        std::cout << "input = " << vm["input"].as<std::string>() << '\n';
      }
      p_in = new std::ifstream( vm["input"].as<std::string>().c_str(), std::ifstream::binary);
    }
    
    if (vm.count("output")) {
      if (g_b_verbose_mode) {
        std::cout << "output = " << vm["output"].as<std::string>() << '\n';
      }
      p_out = new std::ofstream( vm["output"].as<std::string>().c_str(), std::ofstream::binary);
    }

    if (j < 0)
      Sign(t, n, *p_in, *p_out, key);
    else
      Sign(t, n, *p_in, *p_out, key, false, j);
    r = 0;  // success
  } catch (std::exception& ex) {
    r = 1;
    std::string str_what = ex.what();
    if (str_what.empty())
      str_what = "exception without description";
    std::cerr << "exception: " << str_what << "\n";
  } catch (...) {
    r = 2;
    std::cerr << "unknown exception\n";
  }
  if (p_in != &std::cin)
    delete (std::ifstream*)p_in;
  if (p_out != &std::cout)
    delete (std::ofstream*)p_out;
  return r;
}
