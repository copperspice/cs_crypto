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

#include <util/tools/crypto_traits.h>
#include <util/tools/span.h>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <vector>

namespace cs_crypto::util {
template <typename T, typename Cont, typename = std::enable_if_t<cs_crypto::traits::is_iterable_v<Cont>>>
static constexpr bool operator==(const cs_crypto::util::span<T> &view, const Cont &data)
{
   return std::equal(std::begin(view), std::end(view), std::begin(data), std::end(data));
}

template <typename T, std::size_t N>
static constexpr bool operator==(const cs_crypto::util::span<T> &view, const T (&arr)[N])
{
   return std::equal(std::begin(view), std::end(view), std::begin(arr), std::end(arr));
}
}      // namespace cs_crypto::util

TEMPLATE_TEST_CASE("Span provides a view on top of an existing container", "[span][pod]", int, float, char)
{
   using span = cs_crypto::util::span<TestType>;

   SECTION("construction from a C array")
   {
      TestType data[] = {0, 1, 2, 3, 4};
      span my_span{data};

      REQUIRE(my_span == data);
   }

   SECTION("a span is a view so changes are visible")
   {
      TestType data[] = {0, 1, 2, 3, 4};
      span my_span{data};

      data[0] = TestType(42);

      REQUIRE(my_span == data);
   }

   SECTION("construction with data in a vector")
   {
      std::vector<TestType> data = {0, 1, 2, 3, 4};
      span my_span{data.data(), data.size()};

      REQUIRE(my_span == data);
   }
}

TEST_CASE("Span size is correctly determined", "[span][size]")
{
   SECTION("C array")
   {
      std::byte data[] = {std::byte{0}, std::byte{1}, std::byte{2}};
      cs_crypto::util::span<std::byte> my_span{data};

      REQUIRE(my_span.size() == 3);
   }

   SECTION("std::vector")
   {
      std::vector data = {std::byte{0}, std::byte{1}, std::byte{2}};
      cs_crypto::util::span my_span{data.begin(), data.size()};

      REQUIRE(my_span.size() == 3);
   }

   SECTION("Empty std::vector")
   {
      std::vector<std::byte> data;
      cs_crypto::util::span my_span{data.begin(), data.size()};

      REQUIRE(my_span.size() == 0);
   }
}

TEST_CASE("Span iterator distance matches size", "[span][distance][size]")
{
   SECTION("C array")
   {
      std::byte data[] = {std::byte{0}, std::byte{1}, std::byte{2}};
      cs_crypto::util::span<std::byte> my_span{data};

      REQUIRE(my_span.size() == static_cast<std::size_t>(std::distance(my_span.begin(), my_span.end())));
   }

   SECTION("std::vector")
   {
      std::vector data = {std::byte{0}, std::byte{1}, std::byte{2}};
      cs_crypto::util::span my_span{data.data(), data.size()};

      REQUIRE(my_span.size() == static_cast<std::size_t>(std::distance(my_span.begin(), my_span.end())));
   }
}
