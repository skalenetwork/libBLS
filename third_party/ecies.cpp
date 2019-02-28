#include "ecies.h"

namespace signatures {

  void ecies::EncryptMessage( const dev::Public& _k, dev::bytes& io_cipher ) {
    //encrypts message with public key of other account
    s->encryptECIES(_k, io_cipher);
  }

  bool ecies::DecryptMessage( const dev::Secret& _k, dev::bytes& io_text ) {
    //decrypts message with secret key
    return s->decryptECIES(_k, io_text);
  }

} //signatures