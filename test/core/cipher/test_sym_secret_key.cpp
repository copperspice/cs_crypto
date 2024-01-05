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

#include <catch2/catch.hpp>

#include <core/cipher/sym_secret_key.h>

#include <cstddef>
#include <type_traits>

using namespace std::string_literals;

TEMPLATE_TEST_CASE("Secret_key constructor_a", "[secret_key]", char, unsigned char, std::byte)
{
   TestType key_data[16];
   auto key = cs_crypto::cipher::secret_key<16>(key_data);

   REQUIRE(key.size() == 16);
}

TEST_CASE("Secret_key constructor_b", "[secret_key]")
{
   SECTION("valid input")
   {
      auto key = cs_crypto::cipher::secret_key<16>::from_string("xxxxxxxxxxxxxxxx"s);
      REQUIRE(key.has_value());
   }

   SECTION("invalid input")
   {
      auto key = cs_crypto::cipher::secret_key<16>::from_string(""s);
      REQUIRE(!key.has_value());
   }
}

TEST_CASE("Secret_key type traits", "[secret_key]]")
{
   using test_type = typename cs_crypto::cipher::secret_key<16>;

   STATIC_REQUIRE(std::is_move_assignable_v<test_type>);
   STATIC_REQUIRE(std::is_move_constructible_v<test_type>);
   STATIC_REQUIRE(std::is_nothrow_move_assignable_v<test_type>);
   STATIC_REQUIRE(std::is_nothrow_move_constructible_v<test_type>);

   STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<test_type>);
   STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<test_type>);
   STATIC_REQUIRE_FALSE(std::is_nothrow_copy_assignable_v<test_type>);
   STATIC_REQUIRE_FALSE(std::is_nothrow_copy_constructible_v<test_type>);
}
