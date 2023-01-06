/***********************************************************************
*
* Copyright (c) 2021-2023 Tim van Deurzen
* Copyright (c) 2021-2023 Barbara Geller
* Copyright (c) 2021-2023 Ansel Sermersheim
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

#include <core/hash/hash_append.h>
#include <core/hash/hash_traits.h>
#include <drivers/base/drivers.h>
#include <drivers/base/traits.h>
#include <drivers/backend/openssl/config.h>
#include <drivers/backend/botan/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

using namespace cs_crypto::hash;
using namespace cs_crypto::hash::traits;
using namespace cs_crypto::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

template <typename Hash_T, typename Closure_T>
void test_EachType(Closure_T &&closure)
{
   closure(Hash_T::make_context().value());
}

TEMPLATE_TEST_CASE("Hash context_copy", "[hash]",
            enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   using TestDriver = typename driver_for<TestType::value>::hash;

   if constexpr (have_driver_v<TestType::value>) {
      SECTION("copy should compare equal")
      {
         auto object = [](auto hash_context) {
            hash_append(hash_context, "banana");

            auto context_copy = hash_context;

            auto original_result = cs_crypto::util::hex(std::move(hash_context).finalize());
            auto copy_result     = cs_crypto::util::hex(std::move(context_copy).finalize());

            REQUIRE(original_result == copy_result);
         };

         test_EachType<md4_ctx<TestDriver>>(object);
         test_EachType<md5_ctx<TestDriver>>(object);

         test_EachType<sha1_ctx<TestDriver>>(object);

         test_EachType<sha2_224_ctx<TestDriver>>(object);
         test_EachType<sha2_256_ctx<TestDriver>>(object);
         test_EachType<sha2_384_ctx<TestDriver>>(object);
         test_EachType<sha2_512_ctx<TestDriver>>(object);

         test_EachType<sha3_224_ctx<TestDriver>>(object);
         test_EachType<sha3_256_ctx<TestDriver>>(object);
         test_EachType<sha3_384_ctx<TestDriver>>(object);
         test_EachType<sha3_512_ctx<TestDriver>>(object);
      }

      SECTION("changing copy should not change original value")
      {
         auto object = [](auto hash_context) {
            hash_append(hash_context, "banana");

            auto context_copy = hash_context;

            hash_append(context_copy, "apple");

            auto original_result = cs_crypto::util::hex(std::move(hash_context).finalize());
            auto copy_result     = cs_crypto::util::hex(std::move(context_copy).finalize());

            REQUIRE(original_result != copy_result);
         };

         test_EachType<md4_ctx<TestDriver>>(object);
         test_EachType<md5_ctx<TestDriver>>(object);

         test_EachType<sha1_ctx<TestDriver>>(object);

         test_EachType<sha2_224_ctx<TestDriver>>(object);
         test_EachType<sha2_256_ctx<TestDriver>>(object);
         test_EachType<sha2_384_ctx<TestDriver>>(object);
         test_EachType<sha2_512_ctx<TestDriver>>(object);

         test_EachType<sha3_224_ctx<TestDriver>>(object);
         test_EachType<sha3_256_ctx<TestDriver>>(object);
         test_EachType<sha3_384_ctx<TestDriver>>(object);
         test_EachType<sha3_512_ctx<TestDriver>>(object);
      }
   }
}
