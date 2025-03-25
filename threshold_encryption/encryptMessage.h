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

  @file TEPublicKey.h
  @author Sidnei Teixeira
  @date 2025
*/

#ifndef LIBBLS_ENCRYPT_MESSAGE_JS_H
#define LIBBLS_ENCRYPT_MESSAGE_JS_H

#include <atomic>
#include <cstddef>

extern "C" {

/**
 * @brief Encrypts a message using a common public key. Returns the ciphered data bytes in
 * hexadecimal format.
 * @param data The message to be encrypted in hexadecimal format that encodes the underlying bytes
 * @param key The common public key used for encryption in hexadecimal
 */
const char* encryptMessage( const char* data, const char* key );
}


#endif  // LIBBLS_ENCRYPT_MESSAGE_JS_H