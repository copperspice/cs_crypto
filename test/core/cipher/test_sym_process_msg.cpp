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

#include <core/cipher/sym_process_msg.h>
#include <drivers/base/drivers.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>

#include <cstring>
#include <cstddef>
#include <type_traits>
#include <vector>

using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

using namespace std::string_literals;

namespace cs_crypto::testing {

class xor_cipher
{
 public:
   xor_cipher() = default;

   xor_cipher(std::byte mask)
      : m_mask{mask}
   {
   }

   xor_cipher(const xor_cipher &) = delete;
   xor_cipher &operator=(const xor_cipher &) & = delete;

   xor_cipher(xor_cipher &&) noexcept = default;
   xor_cipher &operator=(xor_cipher &&) &noexcept = default;

   ~xor_cipher() = default;

   // An XOR with a mask can both encrypt and decrypt, no need to distinguish.
   auto update(cs_crypto::util::span<std::byte> plaintext) &
   {
      for (const auto b : plaintext) {
         m_state.push_back(b ^ m_mask);
      }
   }

   auto finalize() &&
   {
      return m_state;
   }

 private:
   std::vector<std::byte> m_state;
   std::byte m_mask{0b10101010};

};

struct user_defined {
   std::string m_data;

   template <typename CipherContext>
   constexpr friend void internal_cipher_append(CipherContext &ctx, const user_defined &value)
   {
      cs_crypto::cipher::cipher_append(ctx, value.m_data);
   }
};

template <typename T>
struct identity_cipher {
   std::array<unsigned char, sizeof(T)> m_data;
};

template <typename T>
auto update(identity_cipher<T> &ctx, cs_crypto::util::span<std::byte> plaintext)
{
   std::memcpy(ctx.m_data.data(), plaintext.data(), plaintext.size());
}

template <typename T>
auto finalize(identity_cipher<T> &&ctx)
{
   T retval;
   std::memcpy(&retval, ctx.m_data.data(), ctx.m_data.size());

   return retval;
}

struct sym_process_trivial {
   char value;
};

bool operator==(const sym_process_trivial &lhs, const sym_process_trivial &rhs)
{
   return lhs.value == rhs.value;
}

}  // namespace cs_crypto::testing

TEST_CASE("Cipher append_a", "[cipher]")
{
   using namespace cs_crypto::testing;
   decltype(std::declval<xor_cipher>().finalize()) expected;

   {
      std::array<std::byte, 4> data = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
      auto context                  = xor_cipher{};
      context.update(cs_crypto::util::span(data));
      expected = std::move(context).finalize();
   }

   SECTION("C-style array of known extent")
   {
      std::byte data[] = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
      auto context     = xor_cipher{};

      cs_crypto::cipher::cipher_append(context, data);
      REQUIRE(std::move(context).finalize() == expected);
   }

   SECTION("std::vector")
   {
      std::vector data = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
      auto context     = xor_cipher{};

      cs_crypto::cipher::cipher_append(context, data);
      REQUIRE(std::move(context).finalize() == expected);
   }

   SECTION("std::string")
   {
      std::string data = "abcd";
      auto context     = xor_cipher{};

      cs_crypto::cipher::cipher_append(context, data);
      REQUIRE(std::move(context).finalize() == expected);
   }

   SECTION("User defined types")
   {
      user_defined data{"abcd"s};
      auto context = xor_cipher{};

      cs_crypto::cipher::cipher_append(context, data);
      REQUIRE(std::move(context).finalize() == expected);
   }
}

TEST_CASE("Cipher append_b", "[cipher]")
{
   using namespace cs_crypto::testing;

   SECTION("decrypt should pass")
   {
      auto plaintext     = "my content is secret."s;
      auto plaintext_hex = cs_crypto::util::hex(plaintext);

      auto secret    = std::byte{0b11001100};
      auto encrypter = xor_cipher(secret);

      cs_crypto::cipher::cipher_append(encrypter, plaintext);
      auto ciphertext = std::move(encrypter).finalize();

      REQUIRE(cs_crypto::util::hex(ciphertext) != plaintext_hex);

      auto decrypter = xor_cipher(secret);
      cs_crypto::cipher::cipher_append(decrypter, ciphertext);
      auto recovered = cs_crypto::util::hex(std::move(decrypter).finalize());

      REQUIRE(recovered == plaintext_hex);
   }

   SECTION("decrypt should fail")
   {
      auto plaintext     = "my content is secret."s;
      auto plaintext_hex = cs_crypto::util::hex(plaintext);

      auto secret    = std::byte{0b11001100};
      auto encrypter = xor_cipher(secret);

      cs_crypto::cipher::cipher_append(encrypter, plaintext);
      auto ciphertext = std::move(encrypter).finalize();

      REQUIRE(cs_crypto::util::hex(ciphertext) != plaintext_hex);

      auto wrong_secret = std::byte{0b00110011};
      auto decrypter    = xor_cipher(wrong_secret);
      cs_crypto::cipher::cipher_append(decrypter, ciphertext);
      auto recovered = cs_crypto::util::hex(std::move(decrypter).finalize());

      REQUIRE(recovered != plaintext_hex);
   }
}

TEST_CASE("Cipher append_c", "[cipher]") {
   cs_crypto::testing::identity_cipher<char> ctx;
   cs_crypto::cipher::cipher_append(ctx, 'c');

   REQUIRE(finalize(std::move(ctx)) == 'c');
}

TEMPLATE_TEST_CASE("Cipher append_d", "[cipher]", char, unsigned char, std::byte, cs_crypto::testing::sym_process_trivial)
{
   TestType test_value{42};
   cs_crypto::testing::identity_cipher<TestType> ctx;
   cs_crypto::cipher::cipher_append(ctx, test_value);

   REQUIRE(finalize(std::move(ctx)) == test_value);
}
