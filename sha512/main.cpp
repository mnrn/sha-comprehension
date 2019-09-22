/**
 * @brief SHA512あるごりずむのテストプログラム
 * @date  2016/07/10
 */

#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this
                          // in one cpp file
#include "../matcher.hpp"
#include "sha512.hpp"

// Testing
TEST_CASE("SHA512-Example") {
  SECTION("One-Block Message") {
    const auto bytes = SHA512().hash("abc");
    CHECK_THAT(bytes,
               expect("ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 "
                      "0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd "
                      "454d4423643ce80e 2a9ac94fa54ca49f"));
  }
  SECTION("Multi-Block Message") {
    const auto bytes = SHA512().hash(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi"
        "jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    CHECK_THAT(bytes,
               expect("8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 "
                      "7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a "
                      "c7d329eeb6dd2654 5e96e55b874be909"));
  }
  SECTION("Long Message") {
    const std::vector<std::uint8_t> msg(1000000, 0x61);
    const auto bytes = SHA512().hash(msg);
    CHECK_THAT(bytes,
               expect("e718483d0ce76964 4e2e42c7bc15b4 63 8e1f98b13b204428 "
                      "5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b "
                      "eb009c5c2c49aa2e 4eadb217ad8cc09b"));
  }
}
