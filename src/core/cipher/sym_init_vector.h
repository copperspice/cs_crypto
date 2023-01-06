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

#ifndef CS_CRYPTO_SYM_INIT_VECTOR_H
#define CS_CRYPTO_SYM_INIT_VECTOR_H

#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>

#include <array>
#include <optional>
#include <cstddef>
#include <algorithm>
#include <type_traits>

namespace cs_crypto::cipher {

template <std::size_t SIZE>
class init_vector
{
 public:
   template <typename T>
   constexpr explicit init_vector(const T (&iv)[SIZE])
   {
      if constexpr (cs_crypto::traits::is_uniquely_represented_byte_v<T>) {
         std::copy_n(util::to_byte_ptr(iv), SIZE, m_data.begin());
      } else {
         static_assert(cs_crypto::traits::always_false<T>{}, "Unable to construct init_vector object from array of type T");
      }
   }

   ~init_vector() = default;

   constexpr init_vector(const init_vector &other) = delete;
   constexpr init_vector &operator=(const init_vector &other) & = delete;

   constexpr init_vector(init_vector &&other) = default;
   constexpr init_vector &operator=(init_vector &&other) & = default;

   constexpr static std::optional<init_vector> from_string(const std::string &str)
   {
      if (str.size() != SIZE) {
         return std::nullopt;
      }

      std::optional<init_vector> retval = init_vector{};
      std::copy_n(util::to_byte_ptr(str.data()), SIZE, retval.value().m_data.data());

      return retval;
   }

   constexpr std::size_t size() const
   {
      return SIZE;
   }

   constexpr auto data() const &
   {
      return m_data.data();
   }

 private:
   std::array<std::byte, SIZE> m_data  = {};

   constexpr init_vector()
   {
   }
};

}  // namespace cs_crypto::cipher

#endif
