/***********************************************************************
*
* Copyright (c) 2021-2022 Tim van Deurzen
* Copyright (c) 2021-2022 Ansel Sermersheim
* Copyright (c) 2021-2022 Barbara Geller
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

#include <catch2/catch.hpp>

#include <core/hash/sha3.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

using namespace std::string_literals;
using namespace cs_crypto::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

TEMPLATE_TEST_CASE("Hash SHA3", "[sha3]",
            enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   using TestDriver = typename driver_for<TestType::value>::hash;

   if constexpr (have_driver_v<TestType::value>) {
      SECTION("SHA3_224")
      {
         using cs_crypto::hash::sha3_224;

         // Test cases generated using test utilities in golang, rust and python
         auto test_data = GENERATE(table<std::string, std::string>(
            {
               {"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", ""},
               {"9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b", "a" },
               {"09d27a15bcbab5da828d84dbd66062e5d37049f9b165a65dc581e853", "ab" },
               {"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", "abc" },
               {"dd886b5fd8421fb3871d24e39e53967ce4fc80dd348bedbea0109c0e", "abcd" },
               {"6acfaab70afd8439cea3616b41088bd81c939b272548f6409cf30e57", "abcde" },
               {"ceb3f4cd85af081120bf69ecf76bf61232bd5d810866f0eca3c8907d", "abcdef" },
               {"8a00ff4ec6b96377f1e69b2f72ed3c8da4bfe2f2f8357dc2aac13433", "abcdefg" },
               {"48bf2e8640cffe77b67c6182a6a47f8b5af73f60bd204ef348371d03", "abcdefgh" },
               {"e7b4cd92a5ab3abc2c08841d0f6aa49f88f9f39be40b5a104dd0f114", "abcdefghi" },
               {"354994394a8f8f8228e8eb447f54dbe52dbdf0a96ab1febdf51417e5", "abcdefghij" },
               {"42e169df4ebe0e5f3a9fcf97dfbda432a2caede22dd662473d09378d", "Discard medicine more than two years old." },
               {"c9e1ca5f838ed55352cda8a203d425e8b5b31187a2228cfd1971bd5d", "He who has a shady past knows that nice guys finish last." },
               {"f657781a2da736a9ef86ed1168658042b8cc23e03dceb518ccf0dacb", "I wouldn't marry him with a ten foot pole." },
               {"8d80a4fabea0b4d83567468fea8c8809aa15f69f672cc84d56a14f18", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" },
               {"6a41b37f9c32e82ec32c65648610bb753256a526ad41be5691daafe9", "The days of the digital watch are numbered.  -Tom Stoppard" },
               {"9ef630a116a1fe0292dec2f0ae0a174a850d00d7cef2d5502fa70698", "Nepal premier won't resign." },
               {"9e8519c9920ecff311e2f173ec6d62cd8f81cb3a992a0475c6725fb2", "For every action there is an equal and opposite government program." },
               {"12081c58bff6a2c5823f167897e961335915c2657df41caa0071e563", "His money is twice tainted: 'taint yours and 'taint mine." },
               {"6000aab4424c1d7b4b426bceb0f1d9645d5d4630105aa604730ad156", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" },
               {"9c492ee77b6cb07f0aac2c10c0237095f4f45a597301dc21759ecd55", "It's a tiny change to the code and not completely disgusting. - Bob Manchek" },
               {"6114452873116bcbc66fd73fb23defbbc4d680f2486a67cafa6ac33b", "size:  a.out:  bad magic" },
               {"2a1576bddd4dcb2573d0b8662e12920b6d72fff7c842dc6e7d7eea5b", "The major problem is with sendmail.  -Mark Horton" },
               {"f85bf3715fdef0afd976db07df073aecdf2f19917f16b59bbf41bd75", "Give me a rock, paper and scissors and I will move the world.  CCFestoon" },
               {"c3aef36b6774f0ee1f7efba6a3ff10f217915086c5156bff2631a986", "If the enemy is within range, then so are you." },
               {"1465cc7fe34bda12d0b60d2d114b6ed48b2a8b07ca7dcfafe4cfd118", "It's well we cannot hear the screams/That we create in others' dreams." },
               {"13fcda6ce641fba76e5e19cfb3f6dc29412aad3e0e53b7364058b3d2", "You remind me of a TV show, but that's all right: I watch it anyway." },
               {"2e243b3f2f3b45a3900f19605cf357574dacf7c70e2820ecaa9d2e50", "C is as portable as Stonehedge!!" },
               {"5f21880b60d7e78faca18b97bff9bb32c1d83787870470d7cc5e96e5", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" },
               {"4a628c1adce02899d2a721620deba82178588ae1314bd3d48c13eed9", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" },
               {"b4a355f38a2b188b2a5671c908f942add52cff8929f1e616326c2b22", "How can you write a big system without C++?  -Paul Glick" },
            }));

         auto [expected_output, input] = test_data;
         auto output                   = cs_crypto::util::hex(sha3_224<TestDriver>(input).value());

         REQUIRE(output == expected_output);
      }

      SECTION("SHA3_256")
      {
         using cs_crypto::hash::sha3_256;

         // Test cases generated using test utilities in golang, rust and python
         auto test_data = GENERATE(table<std::string, std::string>(
            {
               {"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", ""},
               {"80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b", "a"},
               {"5c828b33397f4762922e39a60c35699d2550466a52dd15ed44da37eb0bdc61e6", "ab"},
               {"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "abc"},
               {"6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177", "abcd"},
               {"d716ec61e18904a8f58679b71cb065d4d5db72e0e0c3f155a4feff7add0e58eb", "abcde"},
               {"59890c1d183aa279505750422e6384ccb1499c793872d6f31bb3bcaa4bc9f5a5", "abcdef"},
               {"7d55114476dfc6a2fbeaa10e221a8d0f32fc8f2efb69a6e878f4633366917a62", "abcdefg"},
               {"3e2020725a38a48eb3bbf75767f03a22c6b3f41f459c831309b06433ec649779", "abcdefgh"},
               {"f74eb337992307c22bc59eb43e59583a683f3b93077e7f2472508e8c464d2657", "abcdefghi"},
               {"d97f84d48722153838d4ede4f8ac5f9dea8abce77cd7367b2eb0dc500a36fbb4", "abcdefghij"},
               {"e3b22a5c33f8001b503c54c3c301c86fd18fee24785424e211621a4e7184d883", "Discard medicine more than two years old."},
               {"1f024787815858a4498ea92589e4e4ddb573d38707860121b12433414f25be75", "He who has a shady past knows that nice guys finish last."},
               {"bab16090e4b6c44a21b20051d947994b1ddd8c6e7852fdb79e682f5fed42c733", "I wouldn't marry him with a ten foot pole."},
               {"8266964ae94d45ab67821d810c18c263d92827818b5066b0198e1fc5f65124a1", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
               {"86a9fd7ab1d228b1dd452afe8e699d8e4af8bb76115bb0b1abf7e33fcf4f0aba", "The days of the digital watch are numbered.  -Tom Stoppard"},
               {"69ecbdaf520318565349f4196b421a58fcab459f30e305b3c178e258289188ac", "Nepal premier won't resign."},
               {"b35f15904675da9e5f5fc4d445210b837ecc66c227e9cf85054bde3d72890d95", "For every action there is an equal and opposite government program."},
               {"9e2df3744ba4a28e68227aea799bef9d02d834cec1dfdbc762012f48c32b0404", "His money is twice tainted: 'taint yours and 'taint mine."},
               {"ef8a7d7001f7e9135027e903243707e3d6a92960ba5ad5393fddf669607f2788", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
               {"33b94e962e9fa344a4eea13e7a94da863fa65adb1d299311c3174e379129948f", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
               {"50fe5ee41a86d50b517bed295bd84fe44712590e3c4f62b971fa512aa3a4f3db", "size:  a.out:  bad magic"},
               {"7f905932d39118e2c89814f3dad5c27cf0df4f21242b9916e7e15cec61bf3e3c", "The major problem is with sendmail.  -Mark Horton"},
               {"07fc6febe4075ed5b3855bc28c707fdfef9b5875dc8d2f0f6b4accf0cc0b245f", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
               {"924e9ef2ded81ed729c9552878c7aadd6beada29e6c4b059df895752893ec16a", "If the enemy is within range, then so are you."},
               {"cba17fc956a0b78c1922d350529ef54aa9b9832efa315b025ffa698e72862d26", "It's well we cannot hear the screams/That we create in others' dreams."},
               {"a789ec07b1ea22e176d10e80b26adb0d6681682cde21c5c76cb0317ca6ade75a", "You remind me of a TV show, but that's all right: I watch it anyway."},
               {"ab8bd93741935e7fb6566d30e087fca28f5e79ce80b6f477fa50ee1fd14d0f0d", "C is as portable as Stonehedge!!"},
               {"366420300abeef217f5df49f613d1409e007054f0d62bc57525c2a9afc082adf", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
               {"5b76f64d84aa336381bceea0ed17a27352a3314aee76d133f993760913e23b64", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
               {"e68763c08bc834679e350158a57e3caf2444d9a59b7494b47202dcc4e7f55f41", "How can you write a big system without C++?  -Paul Glick"},
            }));

         auto [expected_output, input] = test_data;
         auto output                   = cs_crypto::util::hex(sha3_256<TestDriver>(input).value());

         REQUIRE(output == expected_output);
      }

      SECTION("SHA3_384")
      {
         using cs_crypto::hash::sha3_384;

         // Test cases generated using test utilities in golang, rust and python
         auto test_data = GENERATE(table<std::string, std::string>(
            {
               {"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", ""},
               {"1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9", "a"},
               {"dc30f83fefe3396fa0bd9709bcad28394386aa4e28ae881dc6617b361b16b969fb6a50a109068f13127b6deffbc82d4b", "ab"},
               {"ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", "abc"},
               {"5af1d89732d4d10cc6e92a36756f68ecfbf7ae4d14ed4523f68fc304cccfa5b0bba01c80d0d9b67f9163a5c211cfd65b", "abcd"},
               {"348494236b82edda7602c78ba67fc3838e427c63c23e2c9d9aa5ea6354218a3c2ca564679acabf3ac6bf5378047691c4", "abcde"},
               {"d77460b0ce6109168480e279a81af32facb689ab96e22623f0122ff3a10ead263db6607f83876a843d3264dc2a863805", "abcdef"},
               {"49fbbd02884ae664e095edce429aa5b33d85886466de599eff29e1a0367eb16ff7e749d3966c0d4ade9903bd5867d051", "abcdefg"},
               {"f4d9fc5e9f44eb87fe968fc8e4e4691eb1dab6d821fb77550b527f71ccfb1ba043851bb054f281364c44d8541904db5a", "abcdefgh"},
               {"36e2a92c181adfd48e897f8041e31bbf3a89fbcf50911e686343aa33c165553b5da8cc2d9b2acc943687e540388d4233", "abcdefghi"},
               {"47d08a0d154110ff6dfd8bcea5ad9d14b75918d0b032201b0fd079acf9aebf34cc7bcd32cb1b82f7fff43d7012816e4d", "abcdefghij"},
               {"f61de1a171ab20c26eacd4ef67c3c456bac8e6f88ee45d25a2b8847e50223327659b88c956847582d9ebf1d68f67c351", "Discard medicine more than two years old."},
               {"e1713d2af773e4547254e12a8dee23cbe1fbc296f250c813bf7d9b5fbeffea15eddffda5eda97c50f2a23ba1e4d4c4f2", "He who has a shady past knows that nice guys finish last."},
               {"a585e3642594ccfba843761a4e4424d90e8a706a76bf9282b4e89231d7f1d8ecc4a69e22b82bda88ab069addb2993349", "I wouldn't marry him with a ten foot pole."},
               {"0eb7a0a253f088340ef852cd79d8f5383b789b10c4d192987c2aa85a514e618eeb573e9b227ecc90034c89f09e91671d", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
               {"cd06848928aa99de4bf135a2ee8b10e38e8e317611f7b82c37b51dd72ac8141960460f09da4833356fbd71ad9de97578", "The days of the digital watch are numbered.  -Tom Stoppard"},
               {"7434af599e495e88a9e5d2df9a85721101dc10e9f902c0d87236a84117354378479940822106e19458bab404ddeafc01", "Nepal premier won't resign."},
               {"dda17f288e1ad1b73b185cd21bb9065a760a716b22080dbc0717dde04f766a9275682d79da5fca9e482474a84f2289b7", "For every action there is an equal and opposite government program."},
               {"a5425c4c1c77b1023aea1365004ca63c151f2a67496d3b3d04425efabf489f7815555b4228b21d75b01a42ea5aca7d0c", "His money is twice tainted: 'taint yours and 'taint mine."},
               {"da68554b227b1f33b7c734c49dbd6c455e13c193f49c2729833abe74280bc3e3ee5d4833a9525640cae2fc50813d8294", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
               {"97225141b19b1c745213f272375cd2264a1cde87703cdf8753c7a4a285c94066b8ea02072e1489a707ef26988642ee62", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
               {"3b82d98ba7e70aabc6a1a2b2a555cd792a2592b0f1a32bd503dea0d25b5b038294d3dd50273223c77b300087697524e4", "size:  a.out:  bad magic"},
               {"17975f47a7e5ca424cbc5eb560990b32f81d04f229a122e315eac782d076df6d3dffe09e5f20c2bf7dd22f6b5f763b70", "The major problem is with sendmail.  -Mark Horton"},
               {"388b00147181793e93b045a64ecf255af34588179dca065652d9fcd5e8f7b227fadbafee249e5f14c0c9c70753d26b5c", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
               {"656470e0a07fce2c588e4108e1e136bc709c4bc70dee6bf585728703fd6154a7aa89a4ba5dfdb9a5a6d3c071bf71ce2a", "If the enemy is within range, then so are you."},
               {"8dd38511bee25414bdd1224e95e5901cc9f426bece9d052eee79a4b2930b23c0b1ba3836b0a5fdb6a9a5b2858e5fbddf", "It's well we cannot hear the screams/That we create in others' dreams."},
               {"80f6ee8048aba9a0a872b766f2e2d7b18523717fe774dcd3a8eddddf126d34638927db49d2ae789c4b1c6d9be744b21a", "You remind me of a TV show, but that's all right: I watch it anyway."},
               {"abf4b22bfb9129a55fd5b3b2960b05c61a7e1a48861afcdf4506ffe86658de4679a0f89431c8445122625e9dd59da888", "C is as portable as Stonehedge!!"},
               {"fff1290299d2e40be8b238bb371ec82975391654fc6313c2584cc91cb9c73626bdd3e450681fa5175726127f5166776c", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
               {"cd0ce3b12c461b6fab1b091ab9ad50ffd33c4b301a1b5fd6eba095c51bf340849e95176117d747815673c4e8dae94843", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
               {"d36cd5a343bf6bd83002af57f6b0902779773d46dc3ce231ab6188a3cfe24afe926ab861da03fb96a3baaa39bc15371e", "How can you write a big system without C++?  -Paul Glick"},
            }));

         auto [expected_output, input] = test_data;
         auto output                   = cs_crypto::util::hex(sha3_384<TestDriver>(input).value());

         REQUIRE(output == expected_output);
      }

      SECTION("SHA3_512")
      {
         using cs_crypto::hash::sha3_512;

         // Test cases generated using test utilities in golang, rust and python
         auto test_data = GENERATE(table<std::string, std::string>(
            {
               {"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", ""},
               {"697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a", "a"},
               {"01c87b5e8f094d8725ed47be35430de40f6ab6bd7c6641a4ecf0d046c55cb468453796bb61724306a5fb3d90fbe3726a970e5630ae6a9cf9f30d2aa062a0175e", "ab"},
               {"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", "abc"},
               {"6eb7b86765bf96a8467b72401231539cbb830f6c64120954c4567272f613f1364d6a80084234fa3400d306b9f5e10c341bbdc5894d9b484a8c7deea9cbe4e265", "abcd"},
               {"1d7c3aa6ee17da5f4aeb78be968aa38476dbee54842e1ae2856f4c9a5cd04d45dc75c2902182b07c130ed582d476995b502b8777ccf69f60574471600386639b", "abcde"},
               {"01309a45c57cd7faef9ee6bb95fed29e5e2e0312af12a95fffeee340e5e5948b4652d26ae4b75976a53cc1612141af6e24df36517a61f46a1a05f59cf667046a", "abcdef"},
               {"9c93345c31ecffe20a95eca8db169f1b3ee312dd75fb3494cc1dc2f9a2b6092b6cbebf1299ec6d5ba46b08f728f3075109582bc71b97b4deac5122433732234c", "abcdefg"},
               {"c9f25eee75ab4cf9a8cfd44f4992b282079b64d94647edbd88e818e44f701edeb450818f7272cba7a20205b3671ce1991ce9a6d2df8dbad6e0bb3e50493d7fa7", "abcdefgh"},
               {"4dbdf4a9fc84c246217a68d5a8f3d2a761766cf78752057d60b730a4a8226ef99bbf580c85468f5e93d8fb7873bbdb0de44314e3adf4b94a4fc37c64ca949c6e", "abcdefghi"},
               {"b3e0886fff5ca1df436bf4f6efc124219f908c0abec14036e392a3204f4208b396da0da40e3273f596d4d3db1be4627a16f34230af12ccea92d5d107471551d7", "abcdefghij"},
               {"cdbe0f69c23a9e28868ba75199c7f1a8b3981e2e2acb4ec0e4c0b2909748aa5ad694df8421fa7227b126c8630bd8d7df10abf9af8175d3b14f48d067f0d45751", "Discard medicine more than two years old."},
               {"9c1ff535f65e01009f43962df239d02b62c9a407b243f7aac22902cb40c40d9f31f1b854e8863bf5f9a709bd60c8709bb551663a16649538cbfc0a7ca628a15d", "He who has a shady past knows that nice guys finish last."},
               {"947ed1a0e3ae36ecc4ac4f47555145a168d6a76781f490760073cf552119cedae054991b9b36e7732ad6f4b47c27e6bcd454112cc9afaf31a8d98c63ede6fb9e", "I wouldn't marry him with a ten foot pole."},
               {"642d05bee15e9be5c1753b5d287e7c7d8e4bba71f033051b9639d68d6986b100a835ca2e3a56d92f7b1d0131ea5fe5c6b455a68096909a1aa50be618c3023f3f", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
               {"682e5a3789000931f241764555d5b5a433f8acab2bc0c75ce87098da7dabbbfe75112188ffc09d27a58777a1a2d60f68371b882c379654b4c08241ed2ff1a641", "The days of the digital watch are numbered.  -Tom Stoppard"},
               {"afe1ea67e5fe293d9f777a30fc989120e74298bd9fef145ab1e93428f1c2c96c205410f92fbf01fa7f044acfcc211d9536a6de7608b13107ae29858fe4147673", "Nepal premier won't resign."},
               {"bd0bb214567df7f33574df4b94282aecc9fcdf7994a7bc2ec7e2ca1bd91a80ccf5d9b7e8bb612ba0822be9204fc4b69176c9e1f8f08d0b85112c7d2cfba0ce83", "For every action there is an equal and opposite government program."},
               {"8fa082e5aa0715609f091a4f26a6eead6e2981b0f47fcb6022b44882ee90e9058b751fbfcc18fd80483a0ba8801760f501735e6393af1a51bc2fa13743248aa5", "His money is twice tainted: 'taint yours and 'taint mine."},
               {"c75eb421b65d31ce97b2e07bec9f886872fc99a2bc7f16f96b5b5cde7aff4a956a8148908b45d5c055203f2fb27af18497e094afe7b4f135482b0913550d271c", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
               {"aab837a0b8ebf39793c18e6537e907f9afb689304cb0ac6ab0e3beab252d2a18c031097e5c339c15995e3ab00b89474d1f5ee5f725d33ecc48a8dc8485e7d06d", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
               {"d46926b54fc8f01bf55e1691f7101a8465010c73aa816bf17d85028a7bcbfc7401dce92ba02b67c97ac4084ff44dab6cef59f53807a55a394a38fa5bbdd1b653", "size:  a.out:  bad magic"},
               {"c6d352f69392f517af7ef9b88d241fd721adfecb42776fc3f209d55f9dbd9a1c92e0285c4998a2d1af05dc37634bbad4314a637e8e09a0f8aacd6e119c08b9e3", "The major problem is with sendmail.  -Mark Horton"},
               {"51bbcd6146dd15ff70a67fd2fc7eedfcf49f37949f828fe79405cf0b781a6dac6e37cd5b50d7f0e354efb2d529d89822f8137c90f0973862e33a86bdb43e7ac4", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
               {"fc62ee9035dde34c0f02aafb059e25862bd0e83dcb6541d51def740899654542978087852fd1c7ad0e81dd16afec84ea750adbc5f57f3302657aa9146c42b183", "If the enemy is within range, then so are you."},
               {"81b7246e4de75d4670284f75c0e573bb98b1880c48d053f3d83327b3043c85a4347109665bebda905417e2ab67849b213538cd42ae649b665b29bc8f789b762e", "It's well we cannot hear the screams/That we create in others' dreams."},
               {"fa168294b8b20d30e1ef5a99902e1d9a72871489f9a2f5db239f8ea53a9f61ccb53a34f6ebc65f42bbe171f09cfab7567f4b082b39fd76ee1b75c9f66e2235c5", "You remind me of a TV show, but that's all right: I watch it anyway."},
               {"c393a04c1c1ce02599fed493df145d9c2284f9aa11e84bc5f99e3f455696c47fcd66944bd4df1655239f318a6343db800132e10c469b0ffd8f264e2be3f1a7e6", "C is as portable as Stonehedge!!"},
               {"c527929662b81db100d4dfc4f48a7bb540ef9df7d120accac53bbd1b42cd4b918d2da10015b4f448129bc1eb1d1fd733f1bc1f79f9cfba6e8b324fe84132b118", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
               {"2a0bc1d2be8124c38f8db4a36cb23d92e30114ca4cfce8f42ef850fa66091deb1d41aef4055c75446c44d8c102539113a446cd03d480faf0b75124abdcb1e70a", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
               {"0eda1355f62c135098433b44c2395ee67a6be4fd411396a7bdc5b9f7e04bb5cff251ae2ca3fce25310b2404217a03ed289a4b3e7505891371d6329337d15d0d4", "How can you write a big system without C++?  -Paul Glick"},
            }));

         auto [expected_output, input] = test_data;
         auto output                   = cs_crypto::util::hex(sha3_512<TestDriver>(input).value());

         REQUIRE(output == expected_output);
      }
   }
}
