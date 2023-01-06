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

#ifndef CS_CRYPTO_SYM_PROCESS_MSG_H
#define CS_CRYPTO_SYM_PROCESS_MSG_H

#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>
#include <util/tools/span.h>

#include <utility>
#include <cstddef>
#include <type_traits>
#include <vector>

namespace cs_crypto::cipher {

template <typename T>
using update_member_fn = decltype(std::declval<T &>().update(std::declval<cs_crypto::util::span<std::byte>>()));

template <typename T>
using update_free_fn = decltype(update(std::declval<T &>(), std::declval<cs_crypto::util::span<std::byte>>()));

struct update_dispatch_internal
{
   template <typename CipherContext> constexpr auto operator()(CipherContext &ctx, cs_crypto::util::span<std::byte> bytes) const
   {
      if constexpr (cs_crypto::traits::is_detected_v<update_member_fn, CipherContext>) {
         return ctx.update(bytes);

      } else if constexpr (cs_crypto::traits::is_detected_v<update_free_fn, CipherContext>) {
         return update(ctx, bytes);

      } else {
         static_assert(cs_crypto::traits::always_false<CipherContext>{},
                     "Driver incomplete, unable to locate update() as a method or free function");
      }
   }
};

inline constexpr update_dispatch_internal dispatch_update{};

template <typename CipherContext, typename T,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_cipher_append(CipherContext &ctx, const T v)
{
   return dispatch_update(ctx, {util::to_byte_ptr(std::addressof(v)), 1});
}

template <typename CipherContext, typename T, std::size_t N,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_cipher_append(CipherContext &ctx, const T (&arr)[N])
{
   return dispatch_update(ctx, {util::to_byte_ptr(std::addressof(arr[0])), N});
}

template <typename CipherContext, typename T, std::size_t N,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_cipher_append(CipherContext &ctx, const std::array<T, N> &data)
{
   return dispatch_update(ctx, {util::to_byte_ptr(data.data()), data.size()});
}

template <typename CipherContext, typename T,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_cipher_append(CipherContext &ctx, const std::vector<T> &data)
{
   return dispatch_update(ctx, {util::to_byte_ptr(data.data()), data.size()});
}

template <typename CipherContext>
constexpr auto internal_cipher_append(CipherContext &ctx, const std::string &s)
{
   return dispatch_update(ctx, {util::to_byte_ptr(s.data()), s.size()});
}

template <typename CipherContext, typename T, typename = std::enable_if_t<cs_crypto::traits::is_iterable_v<T>>>
constexpr auto internal_cipher_append(CipherContext &ctx, const T &data)
{
   // error handling left unimplemented until user experience is reported

   for (const auto elem : data) {
      internal_cipher_append(ctx, elem);
   }
}

template <typename CipherContext, typename It, typename End>
constexpr auto internal_cipher_append(CipherContext &ctx, It iter, End end)
{
   // error handling left unimplemented until user experience is reported

   while (iter != end) {
      internal_cipher_append(ctx, *iter);
      iter = std::next(iter);
   }
}

template <typename Ctx>
[[maybe_unused]] inline constexpr bool is_appendable_cipher_context_v =
      std::is_move_assignable_v<Ctx> && std::is_move_constructible_v<Ctx> &&
      (cs_crypto::traits::is_detected_v<update_free_fn, Ctx> || cs_crypto::traits::is_detected_v<update_member_fn, Ctx>);

struct cipher_append_internal
{
   template <typename CipherContext, typename... Ts>
   constexpr auto operator()(CipherContext &&context, Ts &&... args) const
   {
      static_assert(! std::is_same_v<CipherContext, cs_crypto::traits::nonesuch>,
                  "Driver does not support this operation");

      static_assert(is_appendable_cipher_context_v<std::remove_reference_t<CipherContext>>,
                  "Cipher context does not satisfy is_appendable_cipher_context type trait");

      return internal_cipher_append(std::forward<CipherContext>(context), std::forward<Ts>(args)...);
   }
};

inline constexpr const cipher_append_internal cipher_append = {};

}  // namespace cs_crypto::cipher

#endif
