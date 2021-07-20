/***********************************************************************
*
* Copyright (c) 2021 Tim van Deurzen
* Copyright (c) 2021 Ansel Sermersheim
* Copyright (c) 2021 Barbara Geller
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

#ifndef CS_CRYPTO_DRIVERS_TRAITS_H
#define CS_CRYPTO_DRIVERS_TRAITS_H

#include <drivers/base/drivers.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>

#include <type_traits>

namespace cs_crypto::drivers::traits {

template <implementation>
struct have_driver
   : std::false_type
{
};

template <>
struct have_driver<implementation::base>
   : std::true_type
{
};

#if CSCRYPTO_HAVE_BOTAN
   template <>
   struct have_driver<implementation::botan>
      : std::true_type
   {
   };
#endif

#if CSCRYPTO_HAVE_OPENSSL
   template <>
   struct have_driver<implementation::openssl>
      : std::true_type
   {
   };
#endif

template <implementation I>
[[maybe_unused]] constexpr static const bool have_driver_v = have_driver<I>::value;

template <implementation I>
struct driver_for {
   using hash                 = cs_crypto::traits::nonesuch;
   using symmetric_encryption = cs_crypto::traits::nonesuch;
};

}  // namespace cs_crypto::drivers::traits

#endif
