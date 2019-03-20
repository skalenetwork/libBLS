#include <fstream>

#include <bls/bls.h>
#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool g_bVerboseMode = false;

template<class T>
std::string convertToString(T field_elem) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char * tmp = mpz_get_str(NULL, 10, t);
  mpz_clear(t);

  std::string output = tmp;

  return output;
}

void Sign(const size_t t, const size_t n, std::istream& data_file,
          std::ostream& outfile, const std::string& key, bool sign_all = true, int idx = -1) {
  signatures::bls bls_instance = signatures::bls(t, n);

  std::vector <uint8_t> messageData;
  while( ! data_file.eof() ) {
    uint8_t nByte;
    data_file >> nByte;
    messageData.push_back( nByte );
  }

  std::string message( messageData.cbegin(), messageData.cend() );
  libff::alt_bn128_G1 hash = bls_instance.Hashing(message);

  nlohmann::json hash_json;
  hash_json["hash"]["X"] = convertToString<libff::alt_bn128_Fq>(hash.X);
  hash_json["hash"]["Y"] = convertToString<libff::alt_bn128_Fq>(hash.Y);
  hash_json["hash"]["Z"] = convertToString<libff::alt_bn128_Fq>(hash.Z);

  libff::alt_bn128_G1 common_signature;

  libff::alt_bn128_G2 public_key;

  if (sign_all) {
    std::vector<libff::alt_bn128_Fr> secret_key(n);
    
    for (size_t i = 0; i < n; ++i) {
      nlohmann::json secretKey;

      std::ifstream infile(key + std::to_string(i) + ".json");
      infile >> secretKey;

      secret_key[i] = libff::alt_bn128_Fr(secretKey["secret_key"].get<std::string>().c_str());
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

    public_key = bls_instance.KeysRecover(lagrange_coeffs, secret_key).second;
  } else {
    libff::alt_bn128_Fr secret_key;

    nlohmann::json secretKey;

    std::ifstream infile(key + std::to_string(idx) + ".json");
    infile >> secretKey;

    secret_key = libff::alt_bn128_Fr(secretKey["secret_key"].get<std::string>().c_str());

    common_signature = bls_instance.Signing(hash, secret_key);

    public_key = secret_key * libff::alt_bn128_G2::one();
  }
   
  nlohmann::json signature;
  signature["signature"]["X"] = convertToString<libff::alt_bn128_Fq>(common_signature.X);
  signature["signature"]["Y"] = convertToString<libff::alt_bn128_Fq>(common_signature.Y);
  signature["signature"]["Z"] = convertToString<libff::alt_bn128_Fq>(common_signature.Z);

  nlohmann::json public_key_json;
  public_key_json["public_key"]["X"]["c0"] = convertToString<libff::alt_bn128_Fq>(public_key.X.c0);
  public_key_json["public_key"]["X"]["c1"] = convertToString<libff::alt_bn128_Fq>(public_key.X.c1);
  public_key_json["public_key"]["Y"]["c0"] = convertToString<libff::alt_bn128_Fq>(public_key.Y.c0);
  public_key_json["public_key"]["Y"]["c1"] = convertToString<libff::alt_bn128_Fq>(public_key.Y.c1);
  public_key_json["public_key"]["Z"]["c0"] = convertToString<libff::alt_bn128_Fq>(public_key.Z.c0);
  public_key_json["public_key"]["Z"]["c1"] = convertToString<libff::alt_bn128_Fq>(public_key.Z.c1);

  std::ofstream outfile_pk("public_key.json");
  std::ofstream outfile_h("hash.json");

  outfile_pk << public_key_json.dump(4) << "\n";
  outfile_h << hash_json.dump(4) << "\n";

  outfile << signature.dump(4) << "\n";
}

int main(int argc, const char *argv[]) {
  std::istream * pIn = &std::cin;
  std::ostream * pOut = &std::cout;
  int r = 1;
  try {
    boost::program_options::options_description desc("Options");
    desc.add_options()
      ("help", "Show this help screen")
      ("version", "Show version number")
      ("t", boost::program_options::value<size_t>(), "Threshold")
      ("n", boost::program_options::value<size_t>(), "Number of participants")
      ("input", boost::program_options::value<std::string>(), "Input file path; if not specified then use standard input")
      ("j", boost::program_options::value<int>(), "Index of participant to sign; if not specified then all participants")
      ("key", boost::program_options::value<std::string>(), "Directory with secret keys which are secret_key<j>.json ")
      ("output", boost::program_options::value<std::string>(), "Output file path to save signature to; if not specified then use standard output")
      ("v", "Verbose mode (optional)")
      ;

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc <= 1) {
      std::cout
        << "BLS sign tool, version " << EXPAND_AS_STR( BLS_VERSION ) << '\n'
        << "Usage:\n"
        << "   " << argv[0] << " --t <threshold> --n <num_participants> [--j <participant>] [--input <path>] [--output <path>] [--key <path>] [--v]" << '\n'
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

    if (vm.count("key") == 0)
      throw std::runtime_error( "--key is missing (see --help)" );

    if (vm.count("v"))
      g_bVerboseMode = true;

    size_t t = vm["t"].as<size_t>();
    size_t n = vm["n"].as<size_t>();
    if( g_bVerboseMode )
      std::cout
        << "t = " << t << '\n'
        << "n = " << n << '\n'
        << '\n';

    int j = -1;
    if (vm.count("j")) {
      j = vm["j"].as<int>();
      if( g_bVerboseMode )
        std::cout << "j = " << j << '\n';
    }

    std::string key = vm["key"].as<std::string>();
    if( g_bVerboseMode )
      std::cout << "key = " << key << '\n';

    if( vm.count("input") ) {
      if( g_bVerboseMode ) 
        std::cout << "input = " << vm["input"].as<std::string>() << '\n';
      pIn = new std::ifstream( vm["input"].as<std::string>().c_str(), std::ifstream::binary);
    }
    if( vm.count("output") ) {
      if( g_bVerboseMode ) 
        std::cout << "output = " << vm["output"].as<std::string>() << '\n';
      pOut = new std::ofstream( vm["output"].as<std::string>().c_str(), std::ofstream::binary);
    }

    if (j < 0)
      Sign( t, n, *pIn, *pOut, key );
    else
      Sign( t, n, *pIn, *pOut, key, false, j );
    r = 0; // success
  } catch ( std::exception & ex ) {
    r = 1;
    std::string strWhat = ex.what();
    if( strWhat.empty() )
      strWhat = "exception without description";
    std::cerr << "exception: " << strWhat << "\n";
  } catch (...) {
    r = 2;
    std::cerr << "unknown exception\n";
  }
  if( pIn != &std::cin )
    delete (std::ifstream*)pIn;
  if( pOut != &std::cout )
    delete (std::ofstream*)pOut;
  return r;
}
