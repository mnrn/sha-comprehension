#ifndef MATCHER_HPP
#define MATCHER_HPP

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#include "catch2/catch.hpp"

#define FMT_HEADER_ONLY
#include "fmt/format.h"

// The mather class
class BytesMatcher : public Catch::MatcherBase<std::vector<uint8_t>> {
public:
  explicit BytesMatcher(const std::string &digest) : digest(digest) {
    std::copy(digest.cbegin(), digest.cend(), std::back_inserter(rhs));
    rhs.erase(std::remove(rhs.begin(), rhs.end(), ' '), rhs.cend());
  }

  bool match(const std::vector<std::uint8_t> &bytes) const override {
    std::ostringstream ss;
    for (auto &&b : bytes) {
      ss << fmt::format("{:02x}", static_cast<unsigned>(b));
    }
    const auto lhs = ss.str();
    return lhs == rhs;
  }

  virtual std::string describe() const override {
    return "The message digest is " + digest + ".\n";
  }

private:
  std::string digest;
  std::string rhs;
};

// The builder function
inline BytesMatcher expect(const std::string &digest) {
  return BytesMatcher(digest);
}

#endif
