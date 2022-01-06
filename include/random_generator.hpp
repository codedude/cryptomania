#ifndef RNG_RANDOM_GENERATOR
#define RNG_RANDOM_GENERATOR

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>

#include "types.hpp"

namespace RNG
{
class ByteGenerator
{
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 8, boost::multiprecision::cpp_int> gen8b;

public:
    ByteGenerator(int seed = 0) : generator(gen8b(seed)) {}
    ~ByteGenerator() = default;

    byte_t rand()
    {
        return (byte_t)generator();
    }

    void genBytes(byte_t* buffer, int numberOfBytes)
    {
        for (int i = 0; i < numberOfBytes; ++i)
        {
            buffer[i] = this->rand();
        }
    }

private:
    gen8b generator;
};

} // namespace RNG

#endif
