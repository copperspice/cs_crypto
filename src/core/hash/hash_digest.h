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

#ifndef CS_CRYPTO_HASH_DIGEST_H
#define CS_CRYPTO_HASH_DIGEST_H

#include <core/hash/hash_append.h>
#include <util/tools/crypto_traits.h>

#include <optional>
#include <type_traits>

namespace cs_crypto::hash {

template <typename T>
using finalize_member_fn = decltype(std::declval<T&&>().finalize());

template <typename T>
using finalize_free_fn = decltype(finalize(std::declval<T&&>()));

template <typename T>
using make_context_fn = decltype(T::make_context());

struct finalize_dispatch_fn {
   template <typename HashContext>
   auto operator()(HashContext &&ctx) const
   {
      if constexpr (traits::is_detected<finalize_member_fn, HashContext>{}) {
         return std::move(ctx).finalize();

      } else if constexpr (traits::is_detected<finalize_free_fn, HashContext>{}) {
         return finalize(std::move(ctx));

      } else {
         static_assert(traits::always_false<HashContext>{},
                     "Driver incomplete, unable to locate finalize() method or free function");
      }
   }
};

inline constexpr finalize_dispatch_fn finalize{};

template <typename Ctx>
[[maybe_unused]] constexpr static bool is_hash_digest_context_v =
            is_appendable_hash_context_v<Ctx> &&
            traits::is_detected_v<make_context_fn, Ctx> &&
            (traits::is_detected_v<finalize_free_fn, Ctx> || traits::is_detected_v<finalize_member_fn, Ctx>);

template <typename HashContext>
struct hash_digest_internal {
   using result_type = std::optional<cs_crypto::traits::remove_optional_t<decltype(finalize(std::declval<HashContext &&>()))>>;

   template <typename... Ts>
   constexpr auto operator()(Ts &&... args) const -> result_type
   {
      static_assert(! std::is_same_v<HashContext, cs_crypto::traits::nonesuch>,
                  "Selected driver does not support this operation");

      static_assert(is_hash_digest_context_v<HashContext>,
                  "Hash context does not satisfy is_hash_digest_context_v type trait");

      auto maybe_context = HashContext::make_context();
      if (! maybe_context.has_value()) {
         return std::nullopt;
      }

      auto ctx = std::move(maybe_context).value();
      hash_append(ctx, std::forward<Ts>(args)...);

      return finalize(std::move(ctx));
   }
};

template <typename HashDriver, template <typename> typename HashSelector>
inline constexpr hash_digest_internal<HashSelector<HashDriver>> hash_digest = {};

}  // namespace cs_crypto::hash

#endif
