/***********************************************************************
*
* Copyright (c) 2021-2025 Tim van Deurzen
* Copyright (c) 2021-2025 Barbara Geller
* Copyright (c) 2021-2025 Ansel Sermersheim
*
* This file is part of CsCrypto.
*
* CsCrypto is free software which is released under the BSD 2-Clause license.
* For license details refer to the LICENSE provided with this project.
*
* CsCrypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#include <core/hash/md5.h>
#include <core/hash/sha1.h>
#include <core/hash/sha2.h>
#include <core/hash/sha3.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

using namespace cs_crypto;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

int main()
{
#if CSCRYPTO_HAVE_BOTAN && CSCRYPTO_HAVE_OPENSSL
   using botan   = driver_for<drivers::implementation::botan>::hash;
   using openssl = driver_for<drivers::implementation::openssl>::hash;

   std::string filename{"./testfile.txt"};

   {
      std::ofstream out_fs(filename);
      out_fs << "This is a simple test file";
   }

   {
      std::ifstream in_fs(filename);
      std::cout << "md5: "
                << cs_crypto::util::hex(hash::md5<botan>(std::istreambuf_iterator<char>(in_fs),
                   std::istreambuf_iterator<char>()).value());

      std::cout << "\n\n";
   }

   {
      std::ifstream in_fs(filename);
      std::string contents;

      std::copy(std::istreambuf_iterator<char>(in_fs), std::istreambuf_iterator<char>(), std::back_inserter(contents));

      std::cout << "sha1: "     << cs_crypto::util::hex(hash::sha1<botan>(contents).value())     << "\n";
      std::cout << '\n';

      std::cout << "sha2_224: " << cs_crypto::util::hex(hash::sha2_224<botan>(contents).value()) << '\n';
      std::cout << "sha2_256: " << cs_crypto::util::hex(hash::sha2_256<botan>(contents).value()) << '\n';
      std::cout << "sha2_384: " << cs_crypto::util::hex(hash::sha2_384<botan>(contents).value()) << '\n';
      std::cout << "sha2_512: " << cs_crypto::util::hex(hash::sha2_512<botan>(contents).value()) << '\n';
      std::cout << '\n';

      std::cout << "sha3_224: " << cs_crypto::util::hex(hash::sha3_224<openssl>(contents).value()) << '\n';
      std::cout << "sha3_256: " << cs_crypto::util::hex(hash::sha3_256<openssl>(contents).value()) << '\n';
      std::cout << "sha3_384: " << cs_crypto::util::hex(hash::sha3_384<openssl>(contents).value()) << '\n';
      std::cout << "sha3_512: " << cs_crypto::util::hex(hash::sha3_512<openssl>(contents).value()) << '\n';
   }

#else
   std::cout << "Both Botan and OpenSSL drivers are required, examples will not run\n";

#endif
}
