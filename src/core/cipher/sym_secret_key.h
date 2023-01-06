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

#ifndef CS_CRYPTO_SYM_SECRET_KEY_H
#define CS_CRYPTO_SYM_SECRET_KEY_H

#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <type_traits>

namespace cs_crypto::cipher {

template <std::size_t SIZE>
class secret_key
{
 public:
   template <typename T>
   constexpr explicit secret_key(const T (&key)[SIZE])
   {
      if constexpr (cs_crypto::traits::is_uniquely_represented_byte_v<T>) {
         std::copy_n(util::to_byte_ptr(key), SIZE, m_key_data.begin());
      } else {
         static_assert(cs_crypto::traits::always_false<T>{}, "Unable to construct secret key from array of type T");
      }
   }

   ~secret_key() = default;

   constexpr secret_key(const secret_key &other) = delete;
   constexpr secret_key &operator=(const secret_key &other) & = delete;

   constexpr secret_key(secret_key &&other) = default;
   constexpr secret_key &operator=(secret_key &&other) & = default;


   constexpr static std::optional<secret_key> from_string(const std::string &key_data)
   {
      if (key_data.size() < SIZE) {
         return std::nullopt;
      }

      secret_key retval = {};
      std::copy_n(util::to_byte_ptr(key_data.data()), SIZE, retval.m_key_data.data());

      return std::optional<secret_key>(std::move(retval));
   }

   constexpr std::size_t size() const
   {
      return SIZE;
   }

   constexpr auto data() const &
   {
      return m_key_data.data();
   }

 private:
   std::array<std::byte, SIZE> m_key_data  = {};

   constexpr secret_key()
   {
   }
};

}  // namespace cs_crypto::cipher

#endif
