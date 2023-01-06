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

#ifndef CS_CRYPTO_SYM_TRAITS_H
#define CS_CRYPTO_SYM_TRAITS_H

#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>

namespace cs_crypto::cipher::traits {

template <typename T>
using has_key_size = decltype(T::key_size);

template <typename T>
struct key_size {
   static_assert(cs_crypto::traits::is_detected_v<has_key_size, T>, "No key_size constexpr data member found");

   using size_type = decltype(T::key_size);
   constexpr static const size_type value = T::key_size;
};

template <typename T>
[[maybe_unused]] inline constexpr const auto key_size_v = key_size<T>::value;

template <typename T>
using has_iv_size = decltype(T::iv_size);

template <typename T>
struct iv_size {
   static_assert(cs_crypto::traits::is_detected_v<has_iv_size, T>, "No iv_size constexpr data member found");

   using size_type = decltype(T::iv_size);
   constexpr static const size_type value = T::iv_size;
};

template <typename T>
[[maybe_unused]] inline constexpr const auto iv_size_v = iv_size<T>::value;

}  // namespace cs_crypto::cipher::traits

#endif
