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

#ifndef CS_CRYPTO_SYM_ENCRYPT_DECRYPT_H
#define CS_CRYPTO_SYM_ENCRYPT_DECRYPT_H

#include <core/cipher/sym_process_msg.h>
#include <core/cipher/sym_secret_key.h>
#include <core/cipher/sym_init_vector.h>
#include <core/cipher/sym_traits.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>

#include <type_traits>

namespace cs_crypto::cipher {

template <typename T>
using finalize_member_fn = decltype(std::declval<T &&>().finalize());

template <typename T>
using finalize_free_fn = decltype(finalize(std::declval<T &&>()));

struct finalize_dispatch_internal {
   template <typename CipherContext>
   constexpr auto operator()(CipherContext &&ctx) const
   {
      if constexpr (cs_crypto::traits::is_detected<finalize_member_fn, CipherContext>{}) {
         return std::move(ctx).finalize();

      } else if constexpr (cs_crypto::traits::is_detected<finalize_free_fn, CipherContext>{}) {
         return finalize(std::move(ctx));

      } else {
         static_assert(cs_crypto::traits::always_false<CipherContext>{},
                     "Driver incomplete, unable to locate finalize() as a method or free function");
      }
   }
};

inline constexpr finalize_dispatch_internal finalize{};

template <typename Ctx>
[[maybe_unused]] constexpr static bool is_cipher_context_v = is_appendable_cipher_context_v<Ctx> &&
            (cs_crypto::traits::is_detected_v<finalize_free_fn, Ctx> || cs_crypto::traits::is_detected_v<finalize_member_fn, Ctx>);

template <typename CipherContext>
struct encrypt_operation {
   using key_type    = typename CipherContext::key_type;
   using iv_type     = typename CipherContext::iv_type;

   using result_type = std::optional<cs_crypto::traits::remove_optional_t<decltype(finalize(std::declval<CipherContext>()))>>;

   template <typename... Ts>
   constexpr auto operator()(key_type &&secret_key, iv_type &&iv, Ts &&... args) const -> result_type
   {
      static_assert(! std::is_same_v<CipherContext, cs_crypto::traits::nonesuch>,
                  "Selected driver does not support this operation");

      static_assert(is_cipher_context_v<CipherContext>,
                  "Cipher context does not satisfy is_cipher_context_v type trait");

      auto maybe_context = CipherContext::make_context(std::move(secret_key), std::move(iv));
      if (! maybe_context.has_value()) {
         return std::nullopt;
      }

      auto context = std::move(maybe_context).value();
      cipher_append(context, std::forward<Ts>(args)...);

      return finalize(std::move(context));
   }
};

template <typename CipherDriver, typename Cipher, typename Mode>
inline constexpr encrypt_operation<typename CipherDriver::template encrypt<Cipher, Mode>> encrypt;

template <typename CipherDriver, typename Cipher, typename Mode>
inline constexpr encrypt_operation<typename CipherDriver::template decrypt<Cipher, Mode>> decrypt;

}  // namespace cs_crypto::cipher

#endif
