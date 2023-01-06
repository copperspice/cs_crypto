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

#ifndef CS_CRYPTO_DRIVERS_HASH_H
#define CS_CRYPTO_DRIVERS_HASH_H

#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>

namespace cs_crypto::drivers {

struct basic_hash {
   using md4  = cs_crypto::traits::nonesuch;
   using md5  = cs_crypto::traits::nonesuch;

   using sha1 = cs_crypto::traits::nonesuch;

   using sha2_224 = cs_crypto::traits::nonesuch;
   using sha2_256 = cs_crypto::traits::nonesuch;
   using sha2_384 = cs_crypto::traits::nonesuch;
   using sha2_512 = cs_crypto::traits::nonesuch;

   using sha3_224 = cs_crypto::traits::nonesuch;
   using sha3_256 = cs_crypto::traits::nonesuch;
   using sha3_384 = cs_crypto::traits::nonesuch;
   using sha3_512 = cs_crypto::traits::nonesuch;
};

}  // namespace cs_crypto::drivers

#endif
