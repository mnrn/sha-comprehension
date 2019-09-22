/**
 * @brief SHA1あるごりずむのテストプログラム
 * @date  2016/07/09
 */

#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this
                          // in one cpp file
#include "../matcher.hpp"
#include "sha1.hpp"

// Testing
TEST_CASE("SHA1-Example") {
  SECTION("One-Block Message") {
    const auto bytes = SHA1().hash("abc");
    CHECK_THAT(bytes, expect("a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"));
  }
  SECTION("Multi-Block Message") {
    const auto bytes =
        SHA1().hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    CHECK_THAT(bytes, expect("84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"));
  }
  SECTION("Long Message") {
    const std::vector<std::uint8_t> msg(1000000, 0x61);
    const auto bytes = SHA1().hash(msg);
    CHECK_THAT(bytes, expect("34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f"));
  }
}
