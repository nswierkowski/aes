#pragma once

#include <vector>
#include <types.hpp>

namespace padding {

    const byte PADDING_ELEM = 0;

    void add_padding(std::vector<byte>& plain_text);

    void remove_padding(std::vector<byte>& plain_text);
};
