#include "aes.hpp"

namespace AES
{
    template <std::size_t KeySize>
    AES<KeySize>::AES(const Key &key) : key(key)
    {
        key_expansion();
    }

    template <std::size_t KeySize>
    void AES<KeySize>::key_expansion()
    {
        std::array<byte, 4 * 4 * (Nr + 1)> expanded_keys;

        for (std::size_t i = 0; i < KeySize; ++i)
            expanded_keys[i] = key[i];

        std::size_t bytes_generated = KeySize;
        std::size_t rcon_iteration = 1;
        std::array<byte, 4> temp;

        while (bytes_generated < 16 * (Nr + 1))
        {
            for (std::size_t i = 0; i < 4; ++i)
                temp[i] = expanded_keys[bytes_generated - 4 + i];

            if (bytes_generated % KeySize == 0)
            {
                byte k = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = k;

                for (int i = 0; i < 4; ++i) temp[i] = s_box[temp[i]];

                temp[0] ^= rcon[rcon_iteration - 1];
                rcon_iteration++;
            }
            else if (Nk > 6 && (bytes_generated % KeySize) == 16)
            {
                for (int i = 0; i < 4; ++i) temp[i] = s_box[temp[i]];
            }

            for (std::size_t i = 0; i < 4; ++i)
            {
                expanded_keys[bytes_generated] = expanded_keys[bytes_generated - KeySize] ^ temp[i];
                bytes_generated++;
            }
        }

        for (std::size_t i = 0; i <= Nr; ++i)
            for (std::size_t j = 0; j < 16; ++j)
                round_keys[i][j] = expanded_keys[i * 16 + j];
    }

    template <std::size_t KeySize>
    Block AES<KeySize>::encrypt(const Block &plain_text) const
    {
        State state = detail::block_to_state(plain_text);
        detail::add_round_key(state, round_keys[0]);

        for (std::size_t round = 1; round < Nr; ++round)
        {
            detail::sub_bytes(state);
            detail::shift_rows(state);
            detail::mix_columns(state);
            detail::add_round_key(state, round_keys[round]);
        }

        detail::sub_bytes(state);
        detail::shift_rows(state);
        detail::add_round_key(state, round_keys[Nr]);

        return detail::state_to_block(state);
    }

    template <std::size_t KeySize>
    Block AES<KeySize>::decrypt(const Block &encrypted_text) const
    {
        State state = detail::block_to_state(encrypted_text);
        detail::add_round_key(state, round_keys[Nr]);

        for (std::size_t round = Nr - 1; round > 0; --round)
        {
            detail::inv_shift_rows(state);
            detail::inv_sub_bytes(state);
            detail::add_round_key(state, round_keys[round]);
            detail::inv_mix_columns(state);
        }

        detail::inv_shift_rows(state);
        detail::inv_sub_bytes(state);
        detail::add_round_key(state, round_keys[0]);

        return detail::state_to_block(state);
    }

    template class AES<16>;
    template class AES<24>;
    template class AES<32>;
}

namespace AES::detail
{
    void sub_bytes(State &state)
    {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = s_box[state[i][j]];
    }

    void shift_rows(State &state)
    {
        for (int i = 1; i < 4; i++)
        {
            std::array<byte, 4> row_copy = state[i];
            for (int j = 0; j < 4; j++)
                state[i][j] = row_copy[(j + i) % 4];
        }
    }

    constexpr byte xtime(byte x)
    {
        return static_cast<byte>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
    }

    void mix_columns(State &state)
    {
        for (std::size_t c = 0; c < 4; ++c)
        {
            byte a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];

            state[0][c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
            state[1][c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
            state[2][c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
            state[3][c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        }
    }

    void add_round_key(State &state, const RoundKey &round_key)
    {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] ^= round_key[i + 4 * j];
    }

    void inv_sub_bytes(State &state)
    {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = inv_s_box[state[i][j]];
    }

    void inv_shift_rows(State &state)
    {
        for (int i = 1; i < 4; i++)
        {
            std::array<byte, 4> row_copy = state[i];
            for (int j = 0; j < 4; j++)
                state[i][j] = row_copy[(j + 4 - i) % 4];
        }
    }

    constexpr byte mul_gf(byte a, byte b)
    {
        byte result = 0;
        for (int i = 0; i < 8; ++i)
        {
            if (b & 1) result ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return result;
    }

    void inv_mix_columns(State &state)
    {
        for (std::size_t c = 0; c < 4; ++c)
        {
            byte a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];

            state[0][c] = mul_gf(a0, 0x0E) ^ mul_gf(a1, 0x0B) ^ mul_gf(a2, 0x0D) ^ mul_gf(a3, 0x09);
            state[1][c] = mul_gf(a0, 0x09) ^ mul_gf(a1, 0x0E) ^ mul_gf(a2, 0x0B) ^ mul_gf(a3, 0x0D);
            state[2][c] = mul_gf(a0, 0x0D) ^ mul_gf(a1, 0x09) ^ mul_gf(a2, 0x0E) ^ mul_gf(a3, 0x0B);
            state[3][c] = mul_gf(a0, 0x0B) ^ mul_gf(a1, 0x0D) ^ mul_gf(a2, 0x09) ^ mul_gf(a3, 0x0E);
        }
    }

    State block_to_state(const Block &block)
    {
        State state;
        for (std::size_t i = 0; i < BLOCK_SIZE; ++i)
            state[i % 4][i / 4] = block[i];
        return state;
    }

    Block state_to_block(const State &state)
    {
        Block block;
        for (std::size_t row = 0; row < 4; ++row)
            for (std::size_t col = 0; col < 4; ++col)
                block[row + 4 * col] = state[row][col];
        return block;
    }
}