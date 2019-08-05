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

  @file verify_bls.cpp
  @author Oleh Nikolaiev
  @date 2019
*/


#include <fstream>

#include <bls/bls.h>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#include <bls/BLSPublicKey.h>

#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool g_b_verbose_mode = false;

void Verify(const size_t t, const size_t n, std::istream& sign_file) {
  signatures::Bls bls_instance = signatures::Bls(t ,n);

  nlohmann::json signature;
  sign_file >> signature;

  libff::alt_bn128_G1 sign;

  sign.X = libff::alt_bn128_Fq(signature["signature"]["X"].get<std::string>().c_str());
  sign.Y = libff::alt_bn128_Fq(signature["signature"]["Y"].get<std::string>().c_str());
  sign.Z = libff::alt_bn128_Fq::one();

  nlohmann::json hash_in;

  std::ifstream hash_file("hash.json");
  hash_file >> hash_in;

  std::string to_be_hashed = hash_in["message"].get<std::string>();
  std::string hash_str = cryptlite::sha256::hash_hex(to_be_hashed);
  std::array< uint8_t, 32> hash_bytes_arr;
  for (size_t i = 0; i < 32; i++ ){
      hash_bytes_arr.at(i) = static_cast<uint8_t>(hash_str[i]);
  }

  nlohmann::json pk_in;
  std::ifstream pk_file("common_public_key.json");
  pk_file >> pk_in;

  std::vector<std::string> pkey_str;
  for ( size_t i = 0; i < 4; i++){
    pkey_str.push_back(pk_in["insecureCommonBLSPublicKey" + std::to_string(i)]);
  }
  BLSPublicKey common_pkey(std::make_shared<std::vector<std::string>>(pkey_str), t, n);

  if (!sign.is_well_formed()) {
    std::cerr << "PORAZKA\n";
  }

  bool bRes = bls_instance.Verification(std::make_shared<std::array< uint8_t, 32>>(hash_bytes_arr) , sign, *common_pkey.getPublicKey());

  if (g_b_verbose_mode)
    std::cout << "Signature verification result: " << (bRes ? "True" : "False") << '\n';
  if (!bRes)
    throw std::runtime_error("Signature verification failed");
}

int main(int argc, const char *argv[]) {
  std::istream * p_in = &std::cin;
  int r = 1;
  try {
    boost::program_options::options_description desc("Options");
    desc.add_options()
      ("help", "Show this help screen")
      ("version", "Show version number")
      ("t", boost::program_options::value<size_t>(), "Threshold")
      ("n", boost::program_options::value<size_t>(), "Number of participants")
      ("input", boost::program_options::value<std::string>(), "Input file path with BLS signature; if not specified then use standard input")
      ("v", "Verbose mode (optional)")
      ;

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc <= 1) {
      std::cout
        << "BLS signature verification tool, version " << EXPAND_AS_STR( BLS_VERSION ) << '\n'
        << "Usage:\n"
        << "   " << argv[0] << " --t <threshold> --n <num_participants> [--input <path>] [--v]" << '\n'
        << desc << '\n';
      return 0;
    }
    if (vm.count("version")) {
      std::cout
        << EXPAND_AS_STR( BLS_VERSION ) << '\n';
      return 0;
    }

    if (vm.count("t") == 0)
      throw std::runtime_error( "--t is missing (see --help)" );
    if (vm.count("n") == 0)
      throw std::runtime_error( "--n is missing (see --help)" );

    if (vm.count("v"))
      g_b_verbose_mode = true;

    size_t t = vm["t"].as<size_t>();
    size_t n = vm["n"].as<size_t>();
    if( g_b_verbose_mode )
      std::cout
        << "t = " << t << '\n'
        << "n = " << n << '\n'
        << '\n';

    if( vm.count("input") ) {
      if( g_b_verbose_mode ) 
        std::cout << "input = " << vm["input"].as<std::string>() << '\n';
      p_in = new std::ifstream( vm["input"].as<std::string>().c_str(), std::ifstream::binary);
    }

    Verify(t, n, *p_in);
    r = 0; // success
  } catch ( std::exception & ex ) {
    r = 1;
    std::string str_what = ex.what();
    if( str_what.empty() )
      str_what = "exception without description";
    std::cerr << "exception: " << str_what << "\n";
  } catch (...) {
    r = 2;
    std::cerr << "unknown exception\n";
  }
  if( p_in != &std::cin )
    delete (std::ifstream*)p_in;
  return r;
}
