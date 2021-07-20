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

#ifndef CS_CRYPTO_DRIVERS_BOTAN_CONFIG_H
#define CS_CRYPTO_DRIVERS_BOTAN_CONFIG_H

#if CSCRYPTO_HAVE_BOTAN

#include <drivers/base/drivers.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/hash.h>
#include <drivers/backend/botan/aes.h>

namespace cs_crypto::drivers::traits {

template <>
struct driver_for<implementation::botan> {
   using hash                 = cs_crypto::drivers::botan::hash;
   using symmetric_encryption = cs_crypto::drivers::botan::cipher_mode;
};

}  // namespace cs_crypto::drivers::traits

#endif

#endif
