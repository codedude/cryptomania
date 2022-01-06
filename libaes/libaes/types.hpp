#ifndef LIBAES_TYPES_HPP
#define LIBAES_TYPES_HPP

#include <cstdint>
#include <boost/multiprecision/cpp_int.hpp>

using qword_t = boost::multiprecision::uint128_t;
using dword_t = uint64_t;
using word_t = uint32_t;
using byte_t = uint8_t;

#endif
