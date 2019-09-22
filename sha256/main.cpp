/**
 * @brief SHA256あるごりずむのテストプログラム
 * @date  2016/07/10
 */

#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this
                          // in one cpp file
#include "../matcher.hpp"
#include "sha256.hpp"

// Testing
TEST_CASE("SHA256-Example") {
  SECTION("One-Block Message") {
    const auto bytes = SHA256().hash("abc");
    CHECK_THAT(bytes, expect("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 "
                             "96177a9c b410ff61 f20015ad"));
  }
  SECTION("Multi-Block Message") {
    const auto bytes = SHA256().hash(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    CHECK_THAT(bytes, expect("248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 "
                             "64ff2167 f6ecedd4 19db06c1"));
  }
  SECTION("Long Message") {
    const std::vector<std::uint8_t> msg(1000000, 0x61);
    const auto bytes = SHA256().hash(msg);
    CHECK_THAT(bytes, expect("cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 "
                             "a497200e 046d39cc c7112cd0"));
  }
}
