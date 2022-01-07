/***********************************************************************
*
* Copyright (c) 2021-2022 Tim van Deurzen
* Copyright (c) 2021-2022 Ansel Sermersheim
* Copyright (c) 2021-2022 Barbara Geller
*
* This file is part of CsCrypto.
*
* CsCrypto is free software, released under the BSD 2-Clause license.
* For license details refer to LICENSE provided with this project.
*
* CopperSpice is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#include <catch2/catch.hpp>

#include <core/hash/hash_digest.h>
#include <core/hash/hash_traits.h>
#include <drivers/base/drivers.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

#include <string>

using namespace std::string_literals;
using namespace cs_crypto::hash;
using namespace cs_crypto::hash::traits;
using namespace cs_crypto::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

TEMPLATE_TEST_CASE("Hash digest", "[hash]",
            enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   if constexpr (have_driver_v<TestType::value>) {
      using TestDriver = typename driver_for<TestType::value>::hash;

      auto input = "hash_digest_test"s;

      SECTION("MD4")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, md4_ctx>(input).value());
         REQUIRE(output == "a32881bb2530589649da9782c5834260");
      }

      SECTION("MD5")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, md5_ctx>(input).value());
         REQUIRE(output == "8d2430d60177cf7b08224a6df46b743d");
      }

      SECTION("SHA1")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha1_ctx>(input).value());
         REQUIRE(output == "8baef977e4e7fc515f9993b712bcd03812db2e63");
      }

      SECTION("SHA2_224")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha2_224_ctx>(input).value());
         REQUIRE(output == "888d6db588bed7334d8b6a372c97b1c5fcb848e87195877fa7089fdc");
      }

      SECTION("SHA2_256")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha2_256_ctx>(input).value());
         REQUIRE(output == "ad58b461dd4a674baca7e3c5783807e9d987f291cd6c6ac1d94d087a19a82b83");
      }

      SECTION("SHA2_384")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha2_384_ctx>(input).value());
         REQUIRE(output == "6876bc82a42fc8a702cc34d6314fb3b516085c34c3844ce355d0811957b1a07e5396df0d78240671911affe65d1d4caa");
      }

      SECTION("SHA2_512")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha2_512_ctx>(input).value());
         REQUIRE(output == "ba087df41177612be33badb268578dfb9e174cbfe67ccceb95f15116819c03a541e796a90857a5f0109a4bfeb9e88e47751ca662f8caf2a8172cbc61a2bb1155");
      }

      SECTION("SHA3_224")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha3_224_ctx>(input).value());
         REQUIRE(output == "744d4481d23754444cbce4284d7d21a84cc262f4328294ed469b307d");
      }

      SECTION("SHA3_256")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha3_256_ctx>(input).value());
         REQUIRE(output == "641b0de24ba72e3a8775517c82f05c47aa527bb717c57683dda6e97fab82508b");
      }

      SECTION("SHA3_384")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha3_384_ctx>(input).value());
         REQUIRE(output == "5346ea49b2060409b8c3a72cf3700eaaec20faf677eede5979be939968f9814b44adde81eb3e7d75668b92b8fa7e8fa9");
      }

      SECTION("SHA3_512")
      {
         auto output = cs_crypto::util::hex(hash_digest<TestDriver, sha3_512_ctx>(input).value());
         REQUIRE(output == "86ab1cadc0fddba633375f1427630745268288715d27fe507016d25370226ed110dd944741c1dfaf13c94b093bf246af3e25eaf87612cf45e0247f544d599276");
      }
   }
}
