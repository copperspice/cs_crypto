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

#ifndef CS_CRYPTO_HASH_APPEND_H
#define CS_CRYPTO_HASH_APPEND_H

#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/is_detected_traits.h>
#include <util/tools/span.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <type_traits>
#include <vector>

namespace cs_crypto::hash {

template <typename T>
using update_member_fn = decltype(std::declval<T &>().update(std::declval<cs_crypto::util::span<std::byte>>()));

template <typename T>
using update_free_fn = decltype(update(std::declval<T &>(), std::declval<cs_crypto::util::span<std::byte>>()));

struct update_dispatch_fn {
   template <typename HashContext>
   constexpr auto operator()(HashContext &ctx, cs_crypto::util::span<std::byte> bytes) const
   {
      if constexpr (traits::is_detected_v<update_member_fn, HashContext>) {
         return ctx.update(bytes);

      } else if constexpr (traits::is_detected_v<update_free_fn, HashContext>) {
         return update(ctx, bytes);

      } else {
         static_assert(traits::always_false<HashContext>{},
                     "Driver incomplete, unable to locate update() as a method or free function");
      }
   }
};

inline constexpr const update_dispatch_fn dispatch_update{};

template <typename HashContext, typename T,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_hash_append(HashContext &ctx, const T v)
{
   return dispatch_update(ctx, {util::to_byte_ptr(std::addressof(v)), 1});
}

template <typename HashContext, typename T, std::size_t N,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_hash_append(HashContext &ctx, const T (&arr)[N])
{
   return dispatch_update(ctx, {util::to_byte_ptr(std::addressof(arr[0])), N});
}

template <typename HashContext, typename T, std::size_t N,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_hash_append(HashContext &ctx, const std::array<T, N> &data)
{
   return dispatch_update(ctx, {util::to_byte_ptr(data.data()), data.size()});
}

template <typename HashContext, typename T,
            typename = std::enable_if_t<cs_crypto::traits::is_uniquely_represented_byte_v<T>>>
constexpr auto internal_hash_append(HashContext &ctx, const std::vector<T> &data)
{
   return dispatch_update(ctx, {util::to_byte_ptr(data.data()), data.size()});
}

template <typename HashContext>
constexpr auto internal_hash_append(HashContext &ctx, const std::string &s)
{
   return dispatch_update(ctx, {util::to_byte_ptr(s.data()), s.size()});
}

template <typename HashContext, typename T, typename = std::enable_if_t<traits::is_iterable_v<T>>>
constexpr auto internal_hash_append(HashContext &ctx, const T &data)
{
   // error handling left unimplemented until user experience is reported

   for (const auto elem : data) {
      internal_hash_append(ctx, elem);
   }
}

template <typename HashContext, typename It, typename End>
constexpr auto internal_hash_append(HashContext &ctx, It iter, End end)
{
   // error handling left unimplemented until user experience is reported

   while (iter != end) {
      internal_hash_append(ctx, *iter);
      iter = std::next(iter);
   }
}

template <typename Ctx>
[[maybe_unused]] inline constexpr bool is_appendable_hash_context_v =
      std::is_copy_assignable_v<Ctx> && std::is_copy_constructible_v<Ctx> &&
      std::is_move_assignable_v<Ctx> && std::is_move_constructible_v<Ctx> &&
      (traits::is_detected_v<update_free_fn, Ctx> || traits::is_detected_v<update_member_fn, Ctx>);

struct hash_append_internal {
   template <typename HashContext, typename... Ts>
   constexpr auto operator()(HashContext && context, Ts &&... args) const
   {
      static_assert(! std::is_same_v<HashContext, cs_crypto::traits::nonesuch>,
                  "Selected driver does not support this operation");

      static_assert(is_appendable_hash_context_v<std::remove_reference_t<HashContext>>,
                  "Hash context does not satisfy is_appendable_hash_context type trait");

      return internal_hash_append(std::forward<HashContext>(context), std::forward<Ts>(args)...);
   }
};

inline constexpr const hash_append_internal hash_append = {};

}   // namespace cs_crypto::hash

#endif

