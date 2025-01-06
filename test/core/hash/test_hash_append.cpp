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

#include <core/hash/hash_append.h>
#include <util/conversions/hex.h>
#include <util/tools/span.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <vector>

using namespace std::string_literals;

namespace cs_crypto::testing {
// Implements FNV1a hashing algorithm.
struct test_fnv1a {
   std::size_t _state = 14695981039346656037u;
};

void update(test_fnv1a &ctx, cs_crypto::util::span<std::byte> bytes)
{
   for (const auto b : bytes) {
      ctx._state = (ctx._state ^ static_cast<unsigned char>(b)) * 1099511628211u;
   }
}

std::size_t finalize(test_fnv1a const &ctx)
{
   return ctx._state;
}

template <typename T>
struct test_identity_hash {
   std::array<unsigned char, sizeof(T)> m_data;

   test_identity_hash()
      : m_data{}
   {
   }

   void update(cs_crypto::util::span<std::byte> bytes)
   {
      std::memcpy(m_data.data(), bytes.data(), bytes.size());
   }

   T finalize() const
   {
      T result;
      std::memcpy(&result, m_data.data(), m_data.size());

      return result;
   }
};

struct hash_trivial {
   char value;
};

bool operator==(const hash_trivial &lhs, const hash_trivial &rhs)
{
   return lhs.value == rhs.value;
}

struct user_defined {
   std::string m_data;

   template <typename HashContext>
   constexpr friend void internal_hash_append(HashContext &ctx, const user_defined &value)
   {
      cs_crypto::hash::hash_append(ctx, value.m_data);
   }
};

}  // namespace cs_crypto::testing

TEST_CASE("Hash append_a", "[hash]")
{
   using namespace cs_crypto::testing;

   decltype(finalize(std::declval<test_fnv1a>())) expected;

   {
      std::array<std::byte, 4> data = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
      auto context                  = test_fnv1a{};
      update(context, cs_crypto::util::span(data));
      expected = finalize(context);
   }

   SECTION("C-style array of known extent")
   {
      std::byte data[] = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
      auto context     = test_fnv1a{};

      cs_crypto::hash::hash_append(context, data);
      REQUIRE(finalize(context) == expected);
   }

   SECTION("std::vector")
   {
      std::vector data = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
      auto context     = test_fnv1a{};

      cs_crypto::hash::hash_append(context, data);
      REQUIRE(finalize(context) == expected);
   }

   SECTION("std::string")
   {
      std::string data = "abcd";
      auto context     = test_fnv1a{};

      cs_crypto::hash::hash_append(context, data);
      REQUIRE(finalize(context) == expected);
   }

   SECTION("User defined types")
   {
      user_defined data{"abcd"s};
      auto context = test_fnv1a{};

      cs_crypto::hash::hash_append(context, data);
      REQUIRE(finalize(context) == expected);
   }
}

TEMPLATE_TEST_CASE("Hash append_b", "[hash]", char, unsigned char, std::byte, cs_crypto::testing::hash_trivial)
{
   TestType test_value{42};
   cs_crypto::testing::test_identity_hash<TestType> ctx;
   cs_crypto::hash::hash_append(ctx, test_value);

   REQUIRE(ctx.finalize() == test_value);
}

TEST_CASE("Hash append_c", "[hash]")
{
   SECTION("FNV1A")
   {
      cs_crypto::testing::test_fnv1a ctx = {};
      cs_crypto::hash::hash_append(ctx, std::string{"hello world"});

      auto const result = cs_crypto::testing::finalize(ctx);
      REQUIRE(result == 0x779a65e7023cd2e7);
   }
}
