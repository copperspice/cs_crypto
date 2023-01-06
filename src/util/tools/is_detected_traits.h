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

/***********************************************************************
*
* Experimental implementation derived from
* https://en.cppreference.com/w/cpp/experimental/is_detected
*
***********************************************************************/

#ifndef CS_CRYPTO_UTIL_IS_DETECTED_TRAITS_H
#define CS_CRYPTO_UTIL_IS_DETECTED_TRAITS_H

#include <type_traits>

namespace cs_crypto::traits {

struct nonesuch
{
   nonesuch() = delete;

   nonesuch(const nonesuch &) = delete;
   nonesuch(nonesuch &&)      = delete;

   ~nonesuch() = delete;

   void operator=(const nonesuch &) = delete;
   void operator=(nonesuch &&)      = delete;
};

template<class Default, class AlwaysVoid, template<class...> class Op, class... Args>
struct detector
{
  using value_t = std::false_type;
  using type = Default;
};

template<class Default, template<class...> class Op, class... Args>
struct detector<Default, std::void_t<Op<Args...>>, Op, Args...>
{
   using value_t = std::true_type;
   using type = Op<Args...>;
};

template<template<class...> class Op, class... Args>
using is_detected = typename detector<nonesuch, void, Op, Args...>::value_t;

template<template<class...> class Op, class... Args>
using detected_t = typename detector<nonesuch, void, Op, Args...>::type;

template<template<class...> class Op, class... Args>
constexpr bool is_detected_v = is_detected<Op, Args...>::value;

template<class Default, template<class...> class Op, class... Args>
using detected_or = detector<Default, void, Op, Args...>;

template<class Default, template<class...> class Op, class... Args>
using detected_or_t = typename detected_or<Default, Op, Args...>::type;

}   // namespace cs_crypto::traits

#endif