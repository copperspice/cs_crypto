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

#ifndef CS_CRYPTO_UTIL_CRYPTO_TRAITS_H
#define CS_CRYPTO_UTIL_CRYPTO_TRAITS_H

#include <iterator>
#include <optional>

namespace cs_crypto::traits {

template <typename T>
struct always_false : public std::false_type {
};

template <typename T>
struct identity {
   using type = T;
};

template <typename T>
using identity_t = typename identity<T>::type;

template <typename T>
using begin_t = decltype(std::begin(std::declval<T>()));

template <typename T>
using end_t = decltype(std::end(std::declval<T>()));

template <typename T, typename U>
using equality_comparable = decltype(std::declval<T &>() == std::declval<U &>());

template <typename T, typename = void>
struct is_iterable
   : std::false_type
{
};

template <typename T>
struct is_iterable<T, std::void_t<begin_t<T>, end_t<T>, equality_comparable<begin_t<T>, end_t<T>>>>
   : public std::true_type
{
};

template <typename T>
inline constexpr bool is_iterable_v = is_iterable<T>::value;

template <typename T>
struct remove_optional {
   using type = T;
};

template <typename T>
struct remove_optional<std::optional<T>>
   : public remove_optional<T>
{
};

template <typename T>
using remove_optional_t = typename remove_optional<T>::type;

template <auto A>
struct enum_to_type {
   static_assert(std::is_enum_v<decltype(A)>, "Type trait enum_to_type only valid for enums");
   constexpr static const auto value = A;
};

template <typename T>
[[maybe_unused]] inline constexpr bool is_uniquely_represented_byte_v =
    std::is_trivially_copyable_v<T> &&
    std::has_unique_object_representations<T>::value && sizeof(T) == 1;

}  // namespace cs_crypto::traits

#endif
