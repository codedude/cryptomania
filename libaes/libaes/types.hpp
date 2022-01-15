#ifndef LIBAES_TYPES_HPP
#define LIBAES_TYPES_HPP

#include <cstdint>

using byte_t = uint8_t;
using word_t = uint32_t;

#define QWTOBUF(x) ((byte_t*)(&x))
#define QWTOCBUF(x) ((const byte_t*)(&x))

#define QWORD_STATIC_ZERO {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}

typedef struct {
    byte_t b[16];
} qword_t;

#endif
