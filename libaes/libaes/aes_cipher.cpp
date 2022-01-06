#include <libaes/types_helper.hpp>
#include <libaes/libaes.hpp>
#include <libaes/aes_cipher.hpp>

#define CELL(r, c) (r + c * 4)

namespace AES
{

static inline byte_t subByte(byte_t n)
{
    return LOOKUPS::SBOX[n];
}

static inline byte_t invSubByte(byte_t n)
{
    return LOOKUPS::INV_SBOX[n];
}

static void subBytes(byte_t* state)
{
    for (int i = 0; i < 16; ++i)
    {
        state[i] = subByte(state[i]);
    }
}

static void invSubBytes(byte_t* state)
{
    for (int i = 0; i < 16; ++i)
    {
        state[i] = invSubByte(state[i]);
    }
}

static void shiftRows(byte_t* state)
{
    byte_t tmp;

    // Row 1
    tmp = state[CELL(1, 0)];
    state[CELL(1, 0)] = state[CELL(1, 1)];
    state[CELL(1, 1)] = state[CELL(1, 2)];
    state[CELL(1, 2)] = state[CELL(1, 3)];
    state[CELL(1, 3)] = tmp;

    // Row 2
    tmp = state[CELL(2, 0)];
    state[CELL(2, 0)] = state[CELL(2, 2)];
    state[CELL(2, 2)] = tmp;
    tmp = state[CELL(2, 1)];
    state[CELL(2, 1)] = state[CELL(2, 3)];
    state[CELL(2, 3)] = tmp;

    // Row 3
    tmp = state[CELL(3, 3)];
    state[CELL(3, 3)] = state[CELL(3, 2)];
    state[CELL(3, 2)] = state[CELL(3, 1)];
    state[CELL(3, 1)] = state[CELL(3, 0)];
    state[CELL(3, 0)] = tmp;
}

static void invShiftRows(byte_t* state)
{
    byte_t tmp;

    // Row 1
    tmp = state[CELL(1, 3)];
    state[CELL(1, 3)] = state[CELL(1, 2)];
    state[CELL(1, 2)] = state[CELL(1, 1)];
    state[CELL(1, 1)] = state[CELL(1, 0)];
    state[CELL(1, 0)] = tmp;

    // Row 2
    tmp = state[CELL(2, 0)];
    state[CELL(2, 0)] = state[CELL(2, 2)];
    state[CELL(2, 2)] = tmp;
    tmp = state[CELL(2, 1)];
    state[CELL(2, 1)] = state[CELL(2, 3)];
    state[CELL(2, 3)] = tmp;

    // Row 3
    tmp = state[CELL(3, 0)];
    state[CELL(3, 0)] = state[CELL(3, 1)];
    state[CELL(3, 1)] = state[CELL(3, 2)];
    state[CELL(3, 2)] = state[CELL(3, 3)];
    state[CELL(3, 3)] = tmp;
}

/*
    https://en.wikipedia.org/wiki/Rijndael_MixColumns
*/
static void mixColumns(byte_t* state)
{
    for (int r = 0; r < 4; ++r)
    {
        byte_t col[4];
        byte_t colCalc[4];

        for (int c = 0; c < 4; ++c)
        {
            col[c] = state[CELL(c, r)];
            byte_t shouldXor = (byte_t)((signed char)col[c] >> 7);
            colCalc[c] = (col[c] << 1) ^ (0x1b & shouldXor);
        }

        state[CELL(0, r)] = colCalc[0] ^ (colCalc[1] ^ col[1]) ^ col[2] ^ col[3];
        state[CELL(1, r)] = col[0] ^ colCalc[1] ^ (colCalc[2] ^ col[2]) ^ col[3];
        state[CELL(2, r)] = col[0] ^ col[1] ^ colCalc[2] ^ (colCalc[3] ^ col[3]);
        state[CELL(3, r)] = (colCalc[0] ^ col[0]) ^ col[1] ^ col[2] ^ colCalc[3];
    }
}

/*
    https://en.wikipedia.org/wiki/Rijndael_MixColumns
*/
static void invMixColumns(byte_t* state)
{
    const byte_t* MAT = LOOKUPS::INV_MIX_COLUMNS_MATRIX;

    // Iterate over state col
    for (int s_col = 0; s_col < 4; ++s_col)
    {
        // Cache current state column
        byte_t col[4] = { state[CELL(0, s_col)], state[CELL(1, s_col)], state[CELL(2, s_col)], state[CELL(3, s_col)] };

        // Iterate over MAT row
        for (int r = 0; r < 4; ++r)
        {
            byte_t cell = 0;
            // Iterate over MAT col AND state row
            for (int c = 0; c < 4; ++c)
            {
                byte_t a = MAT[CELL(c, r)];
                byte_t b = col[c];
                byte_t p = 0;
                bool carry;
                while (a && b)
                {
                    if (b & 0x01)
                        p ^= a;
                    b >>= 1;
                    carry = (a & 0x80);
                    a <<= 1;
                    if (carry)
                        a ^= 0x1b;
                }
                cell ^= p;
            }
            state[CELL(r, s_col)] = cell;
        }
    }
}

static inline word_t subWord(word_t n)
{
    return bytesToWord(
        subByte(n >> 24),
        subByte((n >> 16) & 0xff),
        subByte((n >> 8) & 0xff),
        subByte(n & 0xff));
}

static void addRoundKey(byte_t* state, const word_t* keySchedule, int round)
{
    for (int i = 0; i < 4; ++i)
    {
        word_t tmp = bytesToWord(state[CELL(0, i)], state[CELL(1, i)], state[CELL(2, i)], state[CELL(3, i)]);
        tmp = tmp ^ keySchedule[4 * round + i];
        state[CELL(0, i)] = tmp >> 24;
        state[CELL(1, i)] = (tmp >> 16) & 0xFF;
        state[CELL(2, i)] = (tmp >> 8) & 0xFF;
        state[CELL(3, i)] = tmp & 0xFF;
    }
}

void keyExpansion(const byte_t* key, word_t* ksch, int kschSize, int Nk)
{
#define ROTWORD(x) (((x) << 8) | ((x) >> 24))

    int i;
    for (i = 0; i < Nk; ++i)
    {
        ksch[i] = bytesToWord(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
    }

    for (i = Nk; i < kschSize; ++i)
    {
        word_t tmp = ksch[i - 1];
        if (i % Nk == 0)
        {
            tmp = subWord(ROTWORD(tmp)) ^ LOOKUPS::RCON[i / Nk - 1];
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            tmp = subWord(tmp);
        }
        ksch[i] = ksch[(i + kschSize - Nk) % kschSize] ^ tmp;
    }

#undef ROTWORD
}

void cipherBlock(byte_t* state, const word_t* keySchedule, int Nr)
{
    // std::cout << "0 - Input: " << bytesToHexString(state, 16) << std::endl;
    addRoundKey(state, keySchedule, 0);
    // std::cout << "0 - k_sch: " << bytesToHexString(state, 16) << std::endl
    //     << std::endl;

    for (int round = 1; round < Nr; ++round)
    {
        subBytes(state);
        // std::cout << round << " - sub: " << bytesToHexString(state, 16) << std::endl;
        shiftRows(state);
        // std::cout << round << " - shi: " << bytesToHexString(state, 16) << std::endl;
        mixColumns(state);
        // std::cout << round << " - mix: " << bytesToHexString(state, 16) << std::endl;
        addRoundKey(state, keySchedule, round);
        // std::cout << round << " - sch: " << bytesToHexString(state, 16) << std::endl
        //           << std::endl;
    }
    subBytes(state);
    // std::cout << "Last - sub: " << bytesToHexString(state, 16) << std::endl;
    shiftRows(state);
    // std::cout << "Last - shi: " << bytesToHexString(state, 16) << std::endl;
    addRoundKey(state, keySchedule, Nr);
    // std::cout << "Last - Output: " << bytesToHexString(state, 16) << std::endl
    //           << std::endl;
}

void decipherBlock(byte_t* state, const word_t* keySchedule, int Nr)
{
    // std::cout << "0 - Input: " << bytesToHexString(state, 16) << std::endl;
    addRoundKey(state, keySchedule, Nr);
    // std::cout << "0 - k_sch: " << bytesToHexString(state, 16) << std::endl
    //   << std::endl;

    for (int round = Nr - 1; round > 0; --round)
    {
        invShiftRows(state);
        // std::cout << round << " - shi: " << bytesToHexString(state, 16) << std::endl;
        invSubBytes(state);
        // std::cout << round << " - sub: " << bytesToHexString(state, 16) << std::endl;
        addRoundKey(state, keySchedule, round);
        // std::cout << round << " - sch: " << bytesToHexString(state, 16) << std::endl;
        invMixColumns(state);
        // std::cout << round << " - mix: " << bytesToHexString(state, 16) << std::endl
        //   << std::endl;
    }

    invShiftRows(state);
    // std::cout << "Last - shi: " << bytesToHexString(state, 16) << std::endl;
    invSubBytes(state);
    // std::cout << "Last - sub: " << bytesToHexString(state, 16) << std::endl;
    addRoundKey(state, keySchedule, 0);
    // std::cout << "Last - Output: " << bytesToHexString(state, 16) << std::endl
    //   << std::endl;
}

} // namespace AES

#undef CELL
