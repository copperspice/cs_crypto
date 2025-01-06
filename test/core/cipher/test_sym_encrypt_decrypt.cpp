/***********************************************************************
*
* Copyright (c) 2021-2025 Tim van Deurzen
* Copyright (c) 2021-2025 Barbara Geller
* Copyright (c) 2021-2025 Ansel Sermersheim
*
* This file is part of CsCrypto.
*
* CsCrypto is free software which is released under the BSD 2-Clause license.
* For license details refer to the LICENSE provided with this project.
*
* CsCrypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#include <catch2/catch.hpp>

#include <core/cipher/block/mode.h>
#include <core/cipher/block/aes.h>
#include <core/cipher/sym_encrypt_decrypt.h>
#include <core/cipher/sym_secret_key.h>
#include <core/cipher/sym_init_vector.h>
#include <drivers/base/drivers.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

#include <cstddef>
#include <type_traits>
#include <vector>

using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;
using namespace cs_crypto::traits;
using namespace cs_crypto::block_cipher;
using namespace cs_crypto::cipher;

namespace cs_crypto::testing {

// Generate a random string of `key_size` chars;
template <int key_size>
std::string random_str() noexcept
{
   std::string retval;
   std::random_device rd;
   std::mt19937 gen(rd());
   std::uniform_int_distribution<short> distrib(0, std::numeric_limits<short>::max() - 1);

   retval.reserve(key_size);

   for (int i = 0; i < key_size / 2; ++i) {
      auto val = distrib(gen);

      retval.push_back(val & 0xFF);
      retval.push_back((val >> 4) & 0xFF);
   }

   return retval;
}

}  // namespace cs_crypto::testing

TEMPLATE_TEST_CASE("Cipher encrypt_decrypt", "[cipher]", enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   if constexpr (have_driver_v<TestType::value>) {
      using TestDriver = typename driver_for<TestType::value>::symmetric_encryption;

      auto input = std::vector<std::byte>{
                  std::byte{0x48}, std::byte{0x45}, std::byte{0x4c}, std::byte{0x4c}, std::byte{0x4f}};

      SECTION("AES128-CBC")
      {
         auto secret = secret_key<aes128::key_size>::from_string(cs_crypto::testing::random_str<aes128::key_size>());
         auto iv     = init_vector<mode::CBC::iv_size>::from_string(cs_crypto::testing::random_str<mode::CBC::iv_size>());

         auto encrypted = cs_crypto::cipher::encrypt<TestDriver, aes128, mode::CBC>(
                     std::move(secret).value(), std::move(iv).value(), input);

         REQUIRE(encrypted.value() != input);

         auto recovered = cs_crypto::cipher::decrypt<TestDriver, aes128, mode::CBC>(
                     std::move(secret).value(),std::move(iv).value(), encrypted.value());

         REQUIRE(recovered.value() == input);
      }

      SECTION("AES192-CBC")
      {
         auto secret = secret_key<aes192::key_size>::from_string(cs_crypto::testing::random_str<aes192::key_size>());
         auto iv     = init_vector<mode::CBC::iv_size>::from_string(cs_crypto::testing::random_str<mode::CBC::iv_size>());

         auto encrypted = cs_crypto::cipher::encrypt<TestDriver, aes192, mode::CBC>(
                     std::move(secret).value(), std::move(iv).value(), input);

         REQUIRE(encrypted.value() != input);

         auto recovered = cs_crypto::cipher::decrypt<TestDriver, aes192, mode::CBC>(
                     std::move(secret).value(), std::move(iv).value(), encrypted.value());

         REQUIRE(recovered.value() == input);
      }

      SECTION("AES256-CBC")
      {
         auto secret = secret_key<aes256::key_size>::from_string(cs_crypto::testing::random_str<aes256::key_size>());
         auto iv     = init_vector<mode::CBC::iv_size>::from_string(cs_crypto::testing::random_str<mode::CBC::iv_size>());

         auto encrypted = cs_crypto::cipher::encrypt<TestDriver, aes256, mode::CBC>(
                     std::move(secret).value(), std::move(iv).value(), input);

         REQUIRE(encrypted.value() != input);

         auto recovered = cs_crypto::cipher::decrypt<TestDriver, aes256, mode::CBC>(
                     std::move(secret).value(), std::move(iv).value(), encrypted.value());

         REQUIRE(recovered.value() == input);
      }
   }
}
