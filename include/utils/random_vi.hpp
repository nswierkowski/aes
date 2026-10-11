#pragma once
#include "types.hpp"
#include <random>
#include <cstdint>

namespace random_vi {

    Block generate_random_vi() {
        thread_local std::mt19937 gen(std::random_device{} ()); 
        std::uniform_int_distribution<> distrib(0, max_byte_value);
        Block vi;

        for (std::size_t i = 0; i < BLOCK_SIZE; i++) {
            vi.at(i) = distrib(gen);
        }

        return vi;
    }
};