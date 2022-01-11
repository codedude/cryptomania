#ifndef CLIAES_RANDOM_GENERATOR_HPP
#define CLIAES_RANDOM_GENERATOR_HPP

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <vector>

#include <libaes/types.hpp>

namespace RNG
{

class RandomGenerator {
public:
    RandomGenerator() : rd(), dis8() {}
    ~RandomGenerator() {}

    std::uint8_t randUInt8() {
        return this->dis8(this->rd);
    }

    void randUInt8Vector(std::vector<std::uint8_t>::iterator begin,
        std::vector<std::uint8_t>::iterator end) {
        for (auto it = begin; it != end; ++it) {
            *it = this->randUInt8();
        }
    }

private:
    boost::random_device rd;
    boost::random::uniform_int_distribution<std::uint8_t> dis8;
};

} // namespace RNG

#endif
