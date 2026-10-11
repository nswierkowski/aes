#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

using byte = std::uint8_t;
constexpr byte max_byte_value = 255;
constexpr std::size_t BLOCK_SIZE = 16;
using Block = std::array<byte, BLOCK_SIZE>;