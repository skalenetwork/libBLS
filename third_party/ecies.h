#include <libdevcrypto/CryptoPP.h>

#include <cstddef>

namespace signatures {

  class ecies {

    public:

      dev::crypto::Secp256k1PP* s;

      void EncryptMessage(const dev::Public& _k, dev::bytes& io_cipher);

      bool DecryptMessage(const dev::Secret& _k, dev::bytes& io_text);

      ecies() {
        s = dev::crypto::Secp256k1PP::get();
      }

  };

} //signatures