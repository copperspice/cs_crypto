/***********************************************************************
*
* Copyright (c) 2021-2024 Tim van Deurzen
* Copyright (c) 2021-2024 Barbara Geller
* Copyright (c) 2021-2024 Ansel Sermersheim
*
* This file is part of CsCrypto.
*
* CsCrypto is free software, released under the BSD 2-Clause license.
* For license details refer to LICENSE provided with this project.
*
* CsCrypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#include <core/cipher/block/aes.h>
#include <core/cipher/sym_encrypt_decrypt.h>
#include <core/cipher/sym_process_msg.h>
#include <core/cipher/sym_secret_key.h>
#include <core/cipher/sym_init_vector.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/byte.h>
#include <util/conversions/hex.h>

#include <iostream>
#include <iterator>
#include <string>
#include <random>
#include <limits>

using namespace cs_crypto::drivers::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::block_cipher;
using namespace cs_crypto::cipher;

// generate a random string with length of key_size
template <int key_size>
std::string random_str() noexcept
{
   std::string retval;
   retval.reserve(key_size);

   std::random_device inputDevice;
   std::mt19937 generateEngine(inputDevice());
   std::uniform_int_distribution<short> outputRange(0, std::numeric_limits<short>::max() - 1);

   for (int i = 0; i < key_size / 2; ++i) {
      short val = outputRange(generateEngine);

      retval.push_back(val & 0xFF);
      retval.push_back((val >> 4) & 0xFF);
   }

   return retval;
}

constexpr static const int key_length = 32;
constexpr static const int iv_length  = 16;

int main()
{
#if CSCRYPTO_HAVE_BOTAN && CSCRYPTO_HAVE_OPENSSL
   std::string key       = random_str<key_length>();
   std::string iv        = random_str<iv_length>();
   std::string plaintext = "A wacky fox and sizeable pig jumped halfway over a blue moon";

   using openssl         = driver_for<implementation::openssl>::symmetric_encryption;
   using botan           = driver_for<implementation::botan>::symmetric_encryption;
   using secret_key_t    = cs_crypto::cipher::secret_key<key_length>;
   using iv_t            = cs_crypto::cipher::init_vector<iv_length>;

   std::vector<std::byte> ciphertext = encrypt<openssl, aes256, mode::CBC>(secret_key_t::from_string(key).value(),
            iv_t::from_string(iv).value(),plaintext).value();

   std::vector<std::byte> resultData = decrypt<botan, aes256, mode::CBC>(secret_key_t::from_string(key).value(),
            iv_t::from_string(iv).value(),ciphertext).value();

   //
   std::string resultString(resultData.size(), '\0');
   memcpy(resultString.data(), resultData.data(), resultData.size());

   std::cout << "plaintext:        " << plaintext << std::endl
             << "key (hex):        " << cs_crypto::util::hex(key) << std::endl
             << "iv (hex):         " << cs_crypto::util::hex(iv)  << std::endl
             << "ciphertext (hex): " << cs_crypto::util::hex(ciphertext) << std::endl
             << "result:           " << resultString << std::endl;
#else
   std::cout << "Both Botan and OpenSSL drivers are required, examples will not run\n";

#endif
}
