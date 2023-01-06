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

#ifndef CS_CRYPTO_DRIVERS_AES_H
#define CS_CRYPTO_DRIVERS_AES_H

#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>

namespace cs_crypto::drivers {

struct basic_cipher_mode {
   template <typename Cipher>
   using CBC = cs_crypto::traits::nonesuch;

   template <typename Cipher>
   using CTR = cs_crypto::traits::nonesuch;

   template <typename Cipher>
   using CFB = cs_crypto::traits::nonesuch;

   template <typename Cipher>
   using ECB = cs_crypto::traits::nonesuch;

   template <typename Cipher>
   using OCB = cs_crypto::traits::nonesuch;

   template <typename Cipher>
   using OFB = cs_crypto::traits::nonesuch;
};

}  // namespace cs_crypto::drivers

#endif
