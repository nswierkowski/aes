#pragma once 

#include <string_view>
#include <array>
#include <optional>
#include <cstdint>

namespace binary_io {

    template <std::size_t N>
    std::optional<std::array<byte, N>> parse_hex(std::string_view hex) {
        if (hex.size() != N * 2) return std::nullopt;

        std::array<byte, N> bytes{};
        for (std::size_t i = 0; i < N; ++i) {
            auto hex_byte = hex.substr(i * 2, 2);
            char* end;
            unsigned long val = std::strtoul(hex_byte.data(), &end, 16);
            bytes[i] = static_cast<byte>(val);
        }
        return bytes;
    }
}